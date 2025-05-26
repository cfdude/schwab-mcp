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
import { SchwabHandler, initializeSchwabAuthClient } from './auth'
import { buildConfig } from './config'
import { logger, makeLogger } from './shared/logger'
import {
	registerAccountTools,
	registerInstrumentTools,
	registerMarketHoursTools,
	registerMoversTools,
	registerOptionsTools,
	registerOrderTools,
	registerPriceHistoryTools,
	registerQuotesTools,
	registerTransactionTools,
	registerUserPreferenceTools,
} from './tools'
import { type ValidatedEnv } from './types/env'

// Align MyMCPProps with schwab-api's TokenSet for consistency
type MyMCPProps = Partial<TokenData>

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
			logger.info('[MyMCP.init] STEP 0: Start')
			this.validatedConfig = buildConfig(this.env)
			makeLogger(this.validatedConfig.LOG_LEVEL ?? 'INFO')
			const redirectUri = this.validatedConfig.SCHWAB_REDIRECT_URI
			logger.info('[MyMCP.init] STEP 1: Env initialized.')

			// Use schwab-api's TokenSet for the function signatures
			const saveTokenForETM = async (tokenSet: TokenData) => {
				if (tokenSet.accessToken) this.props.accessToken = tokenSet.accessToken
				if (tokenSet.refreshToken)
					this.props.refreshToken = tokenSet.refreshToken
				if (tokenSet.expiresAt) this.props.expiresAt = tokenSet.expiresAt
				this.props = { ...this.props }
				logger.info('ETM: Token save to DO props complete', {
					hasAccessToken: !!tokenSet.accessToken,
					hasRefreshToken: !!tokenSet.refreshToken,
					expiresAt: tokenSet.expiresAt
						? new Date(tokenSet.expiresAt).toISOString()
						: 'unknown',
				})
			}

			const loadTokenForETM = async (): Promise<TokenData | null> => {
				if (
					this.props.accessToken &&
					this.props.refreshToken &&
					this.props.expiresAt
				) {
					const tokenData: TokenData = {
						accessToken: this.props.accessToken,
						refreshToken: this.props.refreshToken,
						expiresAt: this.props.expiresAt,
					}
					logger.info('ETM: Token load from DO props complete', {
						hasAccessToken: !!tokenData.accessToken,
						hasRefreshToken: !!tokenData.refreshToken,
						expiresAt: tokenData.expiresAt
							? new Date(tokenData.expiresAt).toISOString()
							: 'unknown',
					})
					return tokenData
				}
				logger.info('ETM: No token data in DO props for ETM load')
				return null
			}

			logger.info('[MyMCP.init] STEP 2: Storage and event handlers defined.')

			// 1. Create ETM instance (synchronous)
			if (!this.tokenManager) {
				logger.info('[MyMCP.init] STEP 3A: Creating new ETM instance...')
				this.tokenManager = initializeSchwabAuthClient(
					this.validatedConfig,
					redirectUri,
					loadTokenForETM,
					saveTokenForETM,
				) // This is synchronous
				logger.info('[MyMCP.init] STEP 3B: New ETM instance created.')
			} else {
				logger.info('[MyMCP.init] STEP 3: Re-using existing ETM instance.')
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
			logger.info('[MyMCP.init] STEP 4: MCP Logger adapted.')

			// 2. Proactively initialize ETM to load tokens BEFORE creating client
			logger.info(
				'[MyMCP.init] STEP 5A: Proactively calling this.tokenManager.initialize() (async)...',
			)
			const etmInitSuccess = this.tokenManager.initialize()
			logger.info(
				`[MyMCP.init] STEP 5B: Proactive ETM initialization complete. Success: ${etmInitSuccess}`,
			)

			// 3. Create SchwabApiClient AFTER tokens are loaded
			if (
				!this.client ||
				(this.client._context?.config as any)?.auth !== this.tokenManager
			) {
				logger.info(
					'[MyMCP.init] STEP 6A: Calling createApiClient (now sync)...',
				)
				// Client creation is now synchronous with the ETM
				this.client = createApiClient({
					config: {
						environment: 'PRODUCTION',
						logger: mcpLogger,
						enableLogging: true,
						logLevel: 'debug',
					},
					auth: this.tokenManager, // Pass the ETM instance
				})
				logger.info('[MyMCP.init] STEP 6B: createApiClient completed (sync).')
			} else {
				logger.info('[MyMCP.init] STEP 6: Re-using existing SchwabApiClient.')
			}

			// 4. Register tools (this.server.tool calls are synchronous)
			logger.info('[MyMCP.init] STEP 7A: Calling registerTools...')
			registerAccountTools(this.client, this.server)
			registerInstrumentTools(this.client, this.server)
			registerMarketHoursTools(this.client, this.server)
			registerMoversTools(this.client, this.server)
			registerOptionsTools(this.client, this.server)
			registerOrderTools(this.client, this.server)
			registerPriceHistoryTools(this.client, this.server)
			registerQuotesTools(this.client, this.server)
			registerTransactionTools(this.client, this.server)
			registerUserPreferenceTools(this.client, this.server)
			logger.info('[MyMCP.init] STEP 7B: registerTools completed.')

			logger.info('[MyMCP.init] STEP 8: MyMCP.init FINISHED SUCCESSFULLY')
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
		logger.info('Gathering diagnostic information')
		const diagnosticInfo: Record<string, any> = {
			timestamp: new Date().toISOString(),
			hasTokenManager: !!this.tokenManager,
			hasClient: !!this.client,
			implementationType: this.tokenManager
				? this.tokenManager.constructor.name
				: 'undefined',
		}
		try {
			const env = this.validatedConfig ?? buildConfig(this.env)
			diagnosticInfo.environment = {
				hasClientId: !!env.SCHWAB_CLIENT_ID,
				hasClientSecret: !!env.SCHWAB_CLIENT_SECRET,
				hasRedirectUri: !!env.SCHWAB_REDIRECT_URI,
				hasCookieKey: !!env.COOKIE_ENCRYPTION_KEY,
				hasOAuthKV: !!env.OAUTH_KV,
			}
		} catch (envError) {
			diagnosticInfo.environmentError =
				envError instanceof Error ? envError.message : String(envError)
		}

		if (this.tokenManager) {
			try {
				// Get diagnostics from EnhancedTokenManager
				if (typeof this.tokenManager.getDiagnostics === 'function') {
					diagnosticInfo.tokenManagerDiagnostics =
						await this.tokenManager.getDiagnostics()

					// Extract high-level token status summary if available
					const diag = diagnosticInfo.tokenManagerDiagnostics
					if (diag && typeof diag === 'object') {
						diagnosticInfo.tokenStatus = {
							hasValidAccessToken: !!(
								diag.hasAccessToken && diag.expiresIn > 0
							),
							hasExpiredAccessToken: !!(
								diag.hasAccessToken && diag.expiresIn <= 0
							),
							hasRefreshToken: !!diag.hasRefreshToken,
							expiresInSeconds: diag.expiresIn,
							lastTokenOperation: diag.lastTokenOperation,
						}
					}
				} else if (
					typeof this.tokenManager.generateTokenReport === 'function'
				) {
					diagnosticInfo.tokenManagerReport =
						await this.tokenManager.generateTokenReport()
				}
			} catch (diagError) {
				diagnosticInfo.tokenManagerDiagnosticError =
					diagError instanceof Error ? diagError.message : String(diagError)
			}
		}

		logger.info('Diagnostic information gathered', {
			timestamp: diagnosticInfo.timestamp,
			tokenStatusSummary: diagnosticInfo.tokenStatus
				? `AccessToken: ${diagnosticInfo.tokenStatus.hasValidAccessToken ? 'Valid' : 'Invalid/Expired'}, RefreshToken: ${diagnosticInfo.tokenStatus.hasRefreshToken ? 'Present' : 'Missing'}`
				: 'No token status available',
		})
		return diagnosticInfo
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
