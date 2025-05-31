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
import {
	APP_NAME,
	API_ENDPOINTS,
	LOGGER_CONTEXTS,
	TOOL_NAMES,
	ENVIRONMENTS,
	LOG_LEVELS,
	CONTENT_TYPES,
	APP_SERVER_NAME,
} from './shared/constants'
import { gatherDiagnostics } from './shared/diagnostics'
import { makeKvTokenStore, type TokenIdentifiers } from './shared/kvTokenStore'
import { makeLogger, LogLevel } from './shared/logger'
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
	private logger = makeLogger(LogLevel.Info).withContext(LOGGER_CONTEXTS.MCP_DO)

	server = new McpServer({
		name: APP_NAME,
		version: '0.0.1',
	})

	async init() {
		try {
			// Register a minimal tool synchronously to ensure Claude Desktop detects tools
			this.server.tool(
				TOOL_NAMES.STATUS,
				'Check Schwab MCP server status',
				{},
				async () => ({
					content: [
						{
							type: CONTENT_TYPES.TEXT,
							text: `${APP_SERVER_NAME} is running. Use tool discovery to see all available tools.`,
						},
					],
				}),
			)
			this.validatedConfig = buildConfig(this.env)
			// Convert string log level to LogLevel enum
			const logLevelStr = this.validatedConfig.LOG_LEVEL ?? 'info'
			// Convert to PascalCase for enum lookup
			const logLevelPascal =
				logLevelStr.charAt(0).toUpperCase() + logLevelStr.slice(1).toLowerCase()
			const logLevel =
				LogLevel[logLevelPascal as keyof typeof LogLevel] ?? LogLevel.Info
			// Update this instance's logger level
			this.logger = makeLogger(logLevel).withContext(LOGGER_CONTEXTS.MCP_DO)
			const redirectUri = this.validatedConfig.SCHWAB_REDIRECT_URI

			this.logger.debug('[MyMCP.init] STEP 0: Start')
			this.logger.debug('[MyMCP.init] STEP 1: Env initialized.')

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
			this.logger.debug('[MyMCP.init] Token identifiers', {
				schwabUserId: this.props.schwabUserId,
				clientId: this.props.clientId,
				hasSchwabUserId: !!this.props.schwabUserId,
				expectedKey: kvToken.kvKey(getTokenIds()),
			})

			// Token save function uses KV store exclusively
			const saveTokenForETM = async (tokenSet: TokenData) => {
				await kvToken.save(getTokenIds(), tokenSet)
				this.logger.debug('ETM: Token save to KV complete', {
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
				this.logger.debug('[ETM Load] Attempting to load token', {
					tokenIds,
					expectedKey: kvToken.kvKey(tokenIds),
				})

				const tokenData = await kvToken.load(tokenIds)
				this.logger.debug('ETM: Token load from KV complete', {
					hasAccessToken: !!tokenData?.accessToken,
					hasRefreshToken: !!tokenData?.refreshToken,
					expiresAt: tokenData?.expiresAt
						? new Date(tokenData.expiresAt).toISOString()
						: 'unknown',
					key: kvToken.kvKey(tokenIds),
					tokenFound: !!tokenData,
					schwabUserId: tokenIds.schwabUserId,
					clientId: tokenIds.clientId,
				})
				return tokenData
			}

			this.logger.debug(
				'[MyMCP.init] STEP 2: Storage and event handlers defined.',
			)

			// 1. Create ETM instance (synchronous)
			const hadExistingTokenManager = !!this.tokenManager
			this.logger.debug('[MyMCP.init] STEP 3A: ETM instance setup', {
				hadExisting: hadExistingTokenManager,
			})
			if (!this.tokenManager) {
				this.tokenManager = initializeSchwabAuthClient(
					this.validatedConfig,
					redirectUri,
					loadTokenForETM,
					saveTokenForETM,
				) // This is synchronous
			}
			this.logger.debug('[MyMCP.init] STEP 3B: ETM instance ready', {
				wasReused: hadExistingTokenManager,
			})

			const mcpLogger: SchwabApiLogger = {
				debug: (message: string, ...args: any[]) =>
					this.logger.debug(message, args.length > 0 ? args[0] : undefined),
				info: (message: string, ...args: any[]) =>
					this.logger.info(message, args.length > 0 ? args[0] : undefined),
				warn: (message: string, ...args: any[]) =>
					this.logger.warn(message, args.length > 0 ? args[0] : undefined),
				error: (message: string, ...args: any[]) =>
					this.logger.error(message, args.length > 0 ? args[0] : undefined),
			}
			this.logger.debug('[MyMCP.init] STEP 4: MCP Logger adapted.')

			// 2. Proactively initialize ETM to load tokens BEFORE creating client
			this.logger.debug(
				'[MyMCP.init] STEP 5A: Proactively calling this.tokenManager.initialize() (async)...',
			)
			const etmInitSuccess = this.tokenManager.initialize()
			this.logger.debug(
				`[MyMCP.init] STEP 5B: Proactive ETM initialization complete. Success: ${etmInitSuccess}`,
			)

			// 2.5. Auto-migrate tokens if we have schwabUserId but token was loaded from clientId key
			if (this.props.schwabUserId && this.props.clientId) {
				try {
					const migrateSuccess = await kvToken.migrate(
						{ clientId: this.props.clientId },
						{ schwabUserId: this.props.schwabUserId },
					)
					this.logger.debug('[MyMCP.init] STEP 5C: Token migration attempt', {
						success: migrateSuccess,
					})
				} catch (migrationError) {
					this.logger.warn('Token migration failed during init', {
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
						environment: ENVIRONMENTS.PRODUCTION,
						logger: mcpLogger,
						enableLogging: true,
						logLevel: LOG_LEVELS.DEBUG,
					},
					auth: this.tokenManager,
				}))

			this.client = globalClient
			this.logger.debug('[MyMCP.init] STEP 6: SchwabApiClient ready.')

			// 4. Register tools (this.server.tool calls are synchronous)
			this.logger.debug('[MyMCP.init] STEP 7A: Calling registerTools...')
			registerMarketTools(this.client, this.server)
			registerTraderTools(this.client, this.server)
			this.logger.debug('[MyMCP.init] STEP 7B: registerTools completed.')
			this.logger.debug('[MyMCP.init] STEP 8: MyMCP.init FINISHED SUCCESSFULLY')
		} catch (error: any) {
			this.logger.error(
				'[MyMCP.init] FINAL CATCH: UNHANDLED EXCEPTION in init()',
				{
					error: error.message,
					stack: error.stack,
				},
			)
			throw error // Re-throw to ensure DO framework sees the failure
		}
	}

	async onReconnect() {
		this.logger.info('Handling reconnection in MyMCP instance')
		try {
			if (!this.tokenManager) {
				this.logger.warn(
					'Token manager not initialized, attempting full initialization',
				)
				await this.init()
				return true
			}
			this.logger.info('Attempting reconnection via token manager')

			try {
				this.logger.info('Attempting to fetch access token as recovery test')
				const token = await this.tokenManager.getAccessToken()
				if (token) {
					this.logger.info(
						'Successfully retrieved access token during reconnection',
					)
					return true
				}
			} catch (tokenError) {
				this.logger.warn('Failed to get access token during reconnection', {
					error:
						tokenError instanceof Error
							? tokenError.message
							: String(tokenError),
				})
			}

			try {
				this.logger.info(
					'Attempting proactive reinitialization of token manager',
				)
				const initResult = await this.tokenManager.initialize()
				this.logger.info(
					`Token manager reinitialization ${initResult ? 'succeeded' : 'failed'}`,
				)
				if (initResult) {
					return true
				}
			} catch (initError) {
				this.logger.warn('Token manager reinitialization failed', {
					error:
						initError instanceof Error ? initError.message : String(initError),
				})
			}

			let diagnostics = {}
			try {
				diagnostics = await this.getDiagnostics()
				this.logger.info('Token diagnostics during reconnection recovery', {
					diagnostics,
				})
			} catch (diagError) {
				this.logger.warn(
					'Failed to get diagnostics during reconnection recovery',
					{
						error:
							diagError instanceof Error
								? diagError.message
								: String(diagError),
					},
				)
			}

			this.logger.warn(
				'Reconnection recovery attempts failed, performing full reinitialization',
			)
			await this.init()
			return true
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			const stack = error instanceof Error ? error.stack : undefined
			this.logger.error('Critical error during reconnection handling', {
				error: message,
				stack,
			})
			try {
				this.logger.warn(
					'Attempting emergency reinitialization after reconnection failure',
				)
				await this.init()
				return true
			} catch (initError) {
				const initMessage =
					initError instanceof Error ? initError.message : String(initError)
				this.logger.error('Emergency reinitialization also failed', {
					error: initMessage,
				})
				return false
			}
		}
	}

	async onSSE(event: any) {
		this.logger.info('SSE connection established or reconnected')
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
	apiRoute: API_ENDPOINTS.SSE,
	apiHandler: MyMCP.mount(API_ENDPOINTS.SSE) as any, // Cast remains due to library typing
	defaultHandler: SchwabHandler as any, // Cast remains
	authorizeEndpoint: API_ENDPOINTS.AUTHORIZE,
	tokenEndpoint: API_ENDPOINTS.TOKEN,
	clientRegistrationEndpoint: API_ENDPOINTS.REGISTER,
})
