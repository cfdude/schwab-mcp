import OAuthProvider from '@cloudflare/workers-oauth-provider'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	createApiClient,
	type SchwabApiClient,
	type EnhancedTokenManager,
	type SchwabApiLogger,
	type TokenData,
} from '@sudowealth/schwab-api'
import { DurableMCP } from 'workers-mcp'
import { type ValidatedEnv } from '../types/env'
import { SchwabHandler, initializeSchwabAuthClient } from './auth'
import { buildConfig } from './config'
import { gatherDiagnostics } from './shared/diagnostics'
import { makeKvTokenStore, type TokenIdentifiers } from './shared/kvTokenStore'
import { logger, LogLevel } from './shared/logger'
import { registerMarketTools, registerTraderTools } from './tools'

/**
 * DO props now contain only IDs needed for token key derivation
 * Tokens are stored exclusively in KV to prevent divergence
 */
type MyMCPProps = {
	/** Schwab user ID when available (preferred for token key) */
	schwabUserId?: string
	/** OAuth client ID (fallback for token key) */
	clientId?: string
}

export class MyMCP extends DurableMCP<MyMCPProps, Env> {
	private tokenManager!: EnhancedTokenManager
	private client!: SchwabApiClient
	private validatedConfig!: ValidatedEnv

	server = new McpServer({
		name: 'Schwab MCP',
		version: '0.0.1',
	})

	async init() {
		try {
			this.validatedConfig = buildConfig(this.env)
			// Convert string log level to LogLevel enum
			const logLevelStr = this.validatedConfig.LOG_LEVEL ?? 'INFO'
			const logLevel =
				LogLevel[logLevelStr.toUpperCase() as keyof typeof LogLevel] ??
				LogLevel.INFO
			// Set the global logger level
			logger.setLevel(logLevel)
			const redirectUri = this.validatedConfig.SCHWAB_REDIRECT_URI

			const isDebug = this.validatedConfig.LOG_LEVEL === 'debug'

			if (isDebug) {
				logger.debug('[MyMCP.init] STEP 0: Start')
				logger.debug('[MyMCP.init] STEP 1: Env initialized.')
			}

			// Create KV token store - single source of truth
			const kvToken = makeKvTokenStore(this.validatedConfig.OAUTH_KV)

			// Ensure clientId is stored in props for token key derivation
			if (!this.props.clientId) {
				this.props.clientId = this.validatedConfig.SCHWAB_CLIENT_ID
				this.props = { ...this.props }
			}

			const getTokenIds = (): TokenIdentifiers => ({
				schwabUserId: this.props.schwabUserId,
				clientId: this.props.clientId,
			})

			// Debug token IDs during initialization
			if (isDebug) {
				logger.debug('[MyMCP.init] Token identifiers', {
					schwabUserId: this.props.schwabUserId,
					clientId: this.props.clientId,
					hasSchwabUserId: !!this.props.schwabUserId,
					expectedKey: kvToken.kvKey(getTokenIds()),
				})
			}

			// Token save function uses KV store exclusively
			const saveTokenForETM = async (tokenSet: TokenData) => {
				await kvToken.save(getTokenIds(), tokenSet)
				logger.debug('ETM: Token save to KV complete', {
					hasAccessToken: !!tokenSet.accessToken,
					hasRefreshToken: !!tokenSet.refreshToken,
					expiresAt: tokenSet.expiresAt
						? new Date(tokenSet.expiresAt).toISOString()
						: 'unknown',
					key: kvToken.kvKey(getTokenIds()),
				})
			}

			// Token load function uses KV store exclusively
			const loadTokenForETM = async (): Promise<TokenData | null> => {
				const tokenIds = getTokenIds()
				if (isDebug) {
					logger.debug('[ETM Load] Attempting to load token', {
						tokenIds,
						expectedKey: kvToken.kvKey(tokenIds),
					})
				}

				const tokenData = await kvToken.load(tokenIds)
				if (tokenData) {
					logger.debug('ETM: Token load from KV complete', {
						hasAccessToken: !!tokenData.accessToken,
						hasRefreshToken: !!tokenData.refreshToken,
						expiresAt: tokenData.expiresAt
							? new Date(tokenData.expiresAt).toISOString()
							: 'unknown',
						key: kvToken.kvKey(tokenIds),
					})
				} else {
					logger.debug('ETM: No token data in KV', {
						key: kvToken.kvKey(tokenIds),
						schwabUserId: tokenIds.schwabUserId,
						clientId: tokenIds.clientId,
					})
				}
				return tokenData
			}

			if (isDebug) {
				logger.debug('[MyMCP.init] STEP 2: Storage and event handlers defined.')
			}

			// 1. Create ETM instance (synchronous)
			if (!this.tokenManager) {
				if (isDebug) {
					logger.debug('[MyMCP.init] STEP 3A: Creating new ETM instance...')
				}
				this.tokenManager = initializeSchwabAuthClient(
					this.validatedConfig,
					redirectUri,
					loadTokenForETM,
					saveTokenForETM,
				) // This is synchronous
				if (isDebug) {
					logger.debug('[MyMCP.init] STEP 3B: New ETM instance created.')
				}
			} else {
				if (isDebug) {
					logger.debug('[MyMCP.init] STEP 3: Re-using existing ETM instance.')
				}
			}

			const mcpLogger: SchwabApiLogger = {
				debug: (message: string, ...args: any[]) =>
					logger.debug(message, args.length > 0 ? args[0] : undefined),
				info: (message: string, ...args: any[]) =>
					logger.info(message, args.length > 0 ? args[0] : undefined),
				warn: (message: string, ...args: any[]) =>
					logger.warn(message, args.length > 0 ? args[0] : undefined),
				error: (message: string, ...args: any[]) =>
					logger.error(message, args.length > 0 ? args[0] : undefined),
			}
			if (isDebug) {
				logger.debug('[MyMCP.init] STEP 4: MCP Logger adapted.')
			}

			// 2. Proactively initialize ETM to load tokens BEFORE creating client
			if (isDebug) {
				logger.debug(
					'[MyMCP.init] STEP 5A: Proactively calling this.tokenManager.initialize() (async)...',
				)
			}
			const etmInitSuccess = this.tokenManager.initialize()
			if (isDebug) {
				logger.debug(
					`[MyMCP.init] STEP 5B: Proactive ETM initialization complete. Success: ${etmInitSuccess}`,
				)
			}

			// 2.5. Auto-migrate tokens if we have schwabUserId but token was loaded from clientId key
			if (this.props.schwabUserId && this.props.clientId) {
				try {
					const migrateSuccess = await kvToken.migrate(
						{ clientId: this.props.clientId },
						{ schwabUserId: this.props.schwabUserId },
					)
					if (migrateSuccess && isDebug) {
						logger.debug('[MyMCP.init] STEP 5C: Token migration completed')
					}
				} catch (migrationError) {
					logger.warn('Token migration failed during init', {
						error:
							migrationError instanceof Error
								? migrationError.message
								: String(migrationError),
					})
				}
			}

			// 3. Create SchwabApiClient AFTER tokens are loaded
			const globalClient =
				globalThis.__schwabClient ??
				(globalThis.__schwabClient = createApiClient({
					config: {
						environment: 'PRODUCTION',
						logger: mcpLogger,
						enableLogging: true,
						logLevel: 'debug',
					},
					auth: this.tokenManager,
				}))

			this.client = globalClient
			if (isDebug) {
				logger.debug('[MyMCP.init] STEP 6: SchwabApiClient ready.')
			}

			// 4. Register tools (this.server.tool calls are synchronous)
			if (isDebug) {
				logger.debug('[MyMCP.init] STEP 7A: Calling registerTools...')
			}
			registerMarketTools(this.client, this.server)
			registerTraderTools(this.client, this.server)
			if (isDebug) {
				logger.debug('[MyMCP.init] STEP 7B: registerTools completed.')
				logger.debug('[MyMCP.init] STEP 8: MyMCP.init FINISHED SUCCESSFULLY')
			}
		} catch (error: any) {
			logger.error('[MyMCP.init] FINAL CATCH: UNHANDLED EXCEPTION in init()', {
				error: error.message,
				stack: error.stack,
			})
			throw error // Re-throw to ensure DO framework sees the failure
		}
	}

	async onReconnect() {
		logger.info('Handling reconnection in MyMCP instance')
		try {
			if (!this.tokenManager) {
				logger.warn(
					'Token manager not initialized, attempting full initialization',
				)
				await this.init()
				return true
			}
			logger.info('Attempting reconnection via token manager')

			try {
				logger.info('Attempting to fetch access token as recovery test')
				const token = await this.tokenManager.getAccessToken()
				if (token) {
					logger.info('Successfully retrieved access token during reconnection')
					return true
				}
			} catch (tokenError) {
				logger.warn('Failed to get access token during reconnection', {
					error:
						tokenError instanceof Error
							? tokenError.message
							: String(tokenError),
				})
			}

			try {
				logger.info('Attempting proactive reinitialization of token manager')
				const initResult = await this.tokenManager.initialize()
				logger.info(
					`Token manager reinitialization ${initResult ? 'succeeded' : 'failed'}`,
				)
				if (initResult) {
					return true
				}
			} catch (initError) {
				logger.warn('Token manager reinitialization failed', {
					error:
						initError instanceof Error ? initError.message : String(initError),
				})
			}

			let diagnostics = {}
			try {
				diagnostics = await this.getDiagnostics()
				logger.info('Token diagnostics during reconnection recovery', {
					diagnostics,
				})
			} catch (diagError) {
				logger.warn('Failed to get diagnostics during reconnection recovery', {
					error:
						diagError instanceof Error ? diagError.message : String(diagError),
				})
			}

			logger.warn(
				'Reconnection recovery attempts failed, performing full reinitialization',
			)
			await this.init()
			return true
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			const stack = error instanceof Error ? error.stack : undefined
			logger.error('Critical error during reconnection handling', {
				error: message,
				stack,
			})
			try {
				logger.warn(
					'Attempting emergency reinitialization after reconnection failure',
				)
				await this.init()
				return true
			} catch (initError) {
				const initMessage =
					initError instanceof Error ? initError.message : String(initError)
				logger.error('Emergency reinitialization also failed', {
					error: initMessage,
				})
				return false
			}
		}
	}

	async onSSE(event: any) {
		logger.info('SSE connection established or reconnected')
		await this.onReconnect()
		return await super.onSSE(event)
	}

	async getDiagnostics() {
		return gatherDiagnostics({
			tokenManager: this.tokenManager,
			client: this.client,
			validatedConfig: this.validatedConfig,
			env: this.env,
			props: this.props,
		})
	}
}

export default new OAuthProvider({
	apiRoute: '/sse',
	apiHandler: MyMCP.mount('/sse') as any, // Cast remains due to library typing
	defaultHandler: SchwabHandler as any, // Cast remains
	authorizeEndpoint: '/authorize',
	tokenEndpoint: '/token',
	clientRegistrationEndpoint: '/register',
})
