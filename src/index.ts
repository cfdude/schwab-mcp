import OAuthProvider from '@cloudflare/workers-oauth-provider'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	createApiClient,
	sanitizeKeyForLog,
	type SchwabApiClient,
	type EnhancedTokenManager,
	type SchwabApiLogger,
	type TokenData,
	type SchwabApiError,
	type SchwabAuthError,
	isSchwabApiError,
	isAuthError,
} from '@sudowealth/schwab-api'
import { DurableMCP } from 'workers-mcp'
import { z } from 'zod'
import { type ValidatedEnv, type Env } from '../types/env'
import { ApiHandler } from './api/handler'
import { SchwabHandler, initializeSchwabAuthClient } from './auth'
import { getConfig } from './config'
import {
	APP_NAME,
	API_ENDPOINTS,
	LOGGER_CONTEXTS,
	TOOL_NAMES,
	ENVIRONMENTS,
	CONTENT_TYPES,
	APP_SERVER_NAME,
} from './shared/constants'
import { makeKvTokenStore, type TokenIdentifiers } from './shared/kvTokenStore'
import { logger, buildLogger, type PinoLogLevel } from './shared/log'
import { logOnlyInDevelopment } from './shared/secureLogger'
import { allToolSpecs, type ToolSpec } from './tools'

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

/** Idle timeout in milliseconds (5 minutes) */
const SSE_IDLE_TIMEOUT_MS = 5 * 60 * 1000

export class MyMCP extends DurableMCP<MyMCPProps, Env> {
	private tokenManager!: EnhancedTokenManager
	private client!: SchwabApiClient
	private validatedConfig!: ValidatedEnv
	private mcpLogger = logger.child(LOGGER_CONTEXTS.MCP_DO)
	private lastActivityTimestamp: number = Date.now()
	/** Our own reference to the SSE transport for idle timeout management */
	private sseTransport: { close: () => Promise<void> } | null = null

	server = new McpServer({
		name: APP_NAME,
		version: '0.0.1',
	})

	/**
	 * Update last activity timestamp and schedule idle timeout alarm.
	 * Called on SSE connect and every tool call.
	 */
	private async updateActivity(): Promise<void> {
		this.lastActivityTimestamp = Date.now()
		const alarmTime = this.lastActivityTimestamp + SSE_IDLE_TIMEOUT_MS
		try {
			await this.ctx.storage.setAlarm(alarmTime)
			this.mcpLogger.debug('Idle timeout alarm scheduled', {
				alarmIn: `${SSE_IDLE_TIMEOUT_MS / 1000}s`,
			})
		} catch (error) {
			this.mcpLogger.warn('Failed to set idle timeout alarm', {
				error: error instanceof Error ? error.message : String(error),
			})
		}
	}

	/**
	 * Durable Object alarm handler - closes SSE connection if idle.
	 * Called by Cloudflare when the scheduled alarm fires.
	 */
	async alarm(): Promise<void> {
		const now = Date.now()
		const idleTime = now - this.lastActivityTimestamp
		const isIdle = idleTime >= SSE_IDLE_TIMEOUT_MS

		this.mcpLogger.info('Idle timeout alarm fired', {
			idleTimeSeconds: Math.floor(idleTime / 1000),
			isIdle,
		})

		if (isIdle && this.sseTransport) {
			this.mcpLogger.info(
				'Closing idle SSE connection to save DO compute costs',
			)
			try {
				await this.sseTransport.close()
				this.sseTransport = null
				this.mcpLogger.info('SSE connection closed successfully')
			} catch (error) {
				this.mcpLogger.warn('Error closing SSE connection', {
					error: error instanceof Error ? error.message : String(error),
				})
			}
		} else if (!isIdle) {
			// Activity occurred since alarm was set, reschedule
			this.mcpLogger.debug('Connection still active, rescheduling alarm')
			await this.updateActivity()
		}
	}

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

			// Register ALL tools immediately so they appear in tools/list
			// The handlers will use this.client which is populated before tools are called
			this.mcpLogger.debug('[MyMCP.init] Registering all tools immediately...')
			allToolSpecs.forEach((spec: ToolSpec<any>) => {
				this.server.tool(
					spec.name,
					spec.description,
					spec.schema instanceof Object && 'shape' in spec.schema
						? spec.schema.shape
						: {},
					async (args: any) => {
						// Update activity timestamp to reset idle timeout
						await this.updateActivity()

						// Ensure client is initialized before tool execution
						if (!this.client) {
							return {
								content: [
									{
										type: 'text' as const,
										text: 'Error: API client not initialized. Please try again.',
									},
								],
								isError: true,
							}
						}
						try {
							const parsedInput = spec.schema.parse(args)
							const data = await spec.call(this.client, parsedInput)

							// Build response content - handle null/undefined data (e.g., 201 Created with no body)
							const content: Array<{ type: 'text'; text: string }> = [
								{
									type: 'text' as const,
									text: `Successfully executed ${spec.name}`,
								},
							]

							// Only add data content if there's actual data to show
							if (data !== null && data !== undefined) {
								content.push({
									type: 'text' as const,
									text: JSON.stringify(data, null, 2),
								})
							} else {
								content.push({
									type: 'text' as const,
									text: 'Operation completed successfully (no response body)',
								})
							}

							return { content }
						} catch (error) {
							const errorMessage =
								error instanceof Error ? error.message : String(error)
							this.mcpLogger.error(`Tool ${spec.name} failed`, {
								error: errorMessage,
							})

							// Build actionable error response for AI agents
							const errorContent: Array<{ type: 'text'; text: string }> = []

							// Handle Zod validation errors with helpful guidance
							if (error instanceof z.ZodError) {
								const issues = error.issues
									.map((issue) => {
										const path = issue.path.join('.')
										return `  - ${path}: ${issue.message}`
									})
									.join('\n')

								errorContent.push({
									type: 'text' as const,
									text:
										`VALIDATION ERROR for ${spec.name}\n\n` +
										`The request parameters failed validation:\n${issues}\n\n` +
										`TIP: Check the tool schema for required fields and their types. ` +
										`Use the schema descriptions to understand which fields are required vs optional.`,
								})
								return { content: errorContent, isError: true }
							}

							// Handle Schwab API errors with rich context
							if (isSchwabApiError(error)) {
								const apiError = error as SchwabApiError
								const status = apiError.status
								const code = apiError.code
								const formattedDetails = apiError.getFormattedDetails?.() || ''
								const debugContext = apiError.getDebugContext?.() || ''
								const requestId = apiError.getRequestId?.()
								const isRetryable = apiError.isRetryable?.() || false

								let actionableGuidance = ''
								switch (status) {
									case 400:
										actionableGuidance =
											'INVALID REQUEST: Check that all required parameters are provided with correct types and formats. ' +
											'For date parameters, use ISO 8601 format (YYYY-MM-DDTHH:mm:ss.sssZ). ' +
											'For order endpoints, ensure session, duration, orderType, orderStrategyType, and orderLegCollection are provided.'
										break
									case 401:
										actionableGuidance =
											'AUTHENTICATION REQUIRED: The access token has expired or is invalid. ' +
											'Schwab tokens expire after 7 days. Re-authentication is required.'
										break
									case 403:
										actionableGuidance =
											'FORBIDDEN: You do not have permission for this operation. ' +
											"This may indicate insufficient account permissions or attempting to access another user's data."
										break
									case 404:
										actionableGuidance =
											'NOT FOUND: The requested resource does not exist. ' +
											'Check that account numbers, order IDs, or transaction IDs are correct.'
										break
									case 429:
										const retryDelay = apiError.getRetryDelayMs?.()
										actionableGuidance =
											`RATE LIMITED: Too many requests. ` +
											(retryDelay
												? `Wait ${Math.ceil(retryDelay / 1000)} seconds before retrying.`
												: 'Wait before retrying.')
										break
									case 500:
									case 502:
									case 503:
									case 504:
										actionableGuidance =
											`SERVER ERROR (${status}): Schwab's servers are experiencing issues. ` +
											(isRetryable
												? 'This error is retryable - wait a moment and try again.'
												: 'Try again later.')
										break
									default:
										actionableGuidance =
											'Unexpected error occurred. Review the error details below.'
								}

								errorContent.push({
									type: 'text' as const,
									text:
										`API ERROR: ${spec.name} failed\n\n` +
										`Status: ${status} (${code})\n` +
										(formattedDetails ? `Details: ${formattedDetails}\n` : '') +
										(debugContext ? `Debug: ${debugContext}\n` : '') +
										(requestId ? `Request ID: ${requestId}\n` : '') +
										`\n${actionableGuidance}`,
								})

								// Include raw body for debugging if available and not too large
								if (apiError.body && typeof apiError.body === 'object') {
									const bodyStr = JSON.stringify(apiError.body, null, 2)
									if (bodyStr.length < 1000) {
										errorContent.push({
											type: 'text' as const,
											text: `Raw response:\n${bodyStr}`,
										})
									}
								}

								// Special handling for token expiration
								if (status === 401) {
									this.mcpLogger.warn(
										'Token appears expired, clearing server-side cache',
									)
									try {
										const kvToken = makeKvTokenStore(
											this.validatedConfig.OAUTH_KV,
										)
										const tokenIds = {
											schwabUserId: this.props.schwabUserId,
											clientId: this.props.clientId,
										}
										await kvToken.clear(tokenIds)
										this.mcpLogger.info(
											'Server-side token cache cleared successfully',
										)
									} catch (clearError) {
										this.mcpLogger.error('Failed to clear token cache', {
											error:
												clearError instanceof Error
													? clearError.message
													: String(clearError),
										})
									}

									errorContent.push({
										type: 'text' as const,
										text:
											`\nTo re-authenticate:\n` +
											`1. Clear local cache: rm -rf ~/.mcp-auth/mcp-remote-*/\n` +
											`2. Restart Claude Desktop\n` +
											`3. The OAuth flow will automatically trigger`,
									})
								}

								return { content: errorContent, isError: true }
							}

							// Handle Schwab Auth errors
							if (isAuthError(error)) {
								const authError = error as SchwabAuthError
								errorContent.push({
									type: 'text' as const,
									text:
										`AUTHENTICATION ERROR: ${spec.name} failed\n\n` +
										`Code: ${authError.code}\n` +
										`Message: ${authError.message}\n\n` +
										`This typically means the authentication tokens need to be refreshed.\n` +
										`To re-authenticate:\n` +
										`1. Clear local cache: rm -rf ~/.mcp-auth/mcp-remote-*/\n` +
										`2. Restart Claude Desktop\n` +
										`3. The OAuth flow will automatically trigger`,
								})
								return { content: errorContent, isError: true }
							}

							// Fallback for other errors - still provide context
							const isTokenExpired =
								errorMessage.includes('Unauthorized') ||
								errorMessage.includes('401') ||
								(errorMessage.includes('token') &&
									errorMessage.toLowerCase().includes('expired')) ||
								errorMessage.includes('invalid_grant') ||
								errorMessage.includes('refresh token')

							if (isTokenExpired) {
								this.mcpLogger.warn(
									'Token appears expired, clearing server-side cache',
								)
								try {
									const kvToken = makeKvTokenStore(
										this.validatedConfig.OAUTH_KV,
									)
									const tokenIds = {
										schwabUserId: this.props.schwabUserId,
										clientId: this.props.clientId,
									}
									await kvToken.clear(tokenIds)
									this.mcpLogger.info(
										'Server-side token cache cleared successfully',
									)
								} catch (clearError) {
									this.mcpLogger.error('Failed to clear token cache', {
										error:
											clearError instanceof Error
												? clearError.message
												: String(clearError),
									})
								}

								return {
									content: [
										{
											type: 'text' as const,
											text:
												`AUTHENTICATION EXPIRED: ${spec.name} failed\n\n` +
												`Schwab tokens are valid for 7 days.\n\n` +
												`To re-authenticate:\n` +
												`1. Clear local cache: rm -rf ~/.mcp-auth/mcp-remote-*/\n` +
												`2. Restart Claude Desktop\n` +
												`3. The OAuth flow will automatically trigger\n\n` +
												`Original error: ${errorMessage}`,
										},
									],
									isError: true,
								}
							}

							// Generic error with helpful context
							return {
								content: [
									{
										type: 'text' as const,
										text:
											`ERROR: ${spec.name} failed\n\n` +
											`Message: ${errorMessage}\n\n` +
											`If this error persists, check:\n` +
											`- Are all required parameters provided?\n` +
											`- Are parameter types correct (strings, numbers, dates)?\n` +
											`- Is the Schwab API available?`,
									},
								],
								isError: true,
							}
						}
					},
				)
			})
			this.mcpLogger.debug(
				`[MyMCP.init] Registered ${allToolSpecs.length} tools`,
			)

			this.validatedConfig = getConfig(this.env)
			// Initialize logger with configured level
			const logLevel = this.validatedConfig.LOG_LEVEL as PinoLogLevel
			const newLogger = buildLogger(logLevel)
			// Replace the singleton logger instance
			Object.assign(logger, newLogger)
			const redirectUri = this.validatedConfig.SCHWAB_REDIRECT_URI

			this.mcpLogger.debug('[MyMCP.init] STEP 0: Start')
			this.mcpLogger.debug('[MyMCP.init] STEP 1: Env initialized.')

			// Create KV token store - single source of truth
			const kvToken = makeKvTokenStore(this.validatedConfig.OAUTH_KV)

			// Ensure clientId is stored in props for token key derivation
			if (!this.props.clientId) {
				this.props.clientId = this.validatedConfig.SCHWAB_CLIENT_ID
				this.props = { ...this.props }
			}

			const getTokenIds = (): TokenIdentifiers => ({
				schwabUserId: this.props.schwabUserId,
				// Always use stable SCHWAB_CLIENT_ID for token lookup, not mcp-remote's clientId
				// mcp-remote creates a new clientId each session, but SCHWAB_CLIENT_ID is constant
				clientId: this.validatedConfig.SCHWAB_CLIENT_ID,
			})

			// Debug token IDs during initialization
			logOnlyInDevelopment(
				this.mcpLogger,
				'debug',
				'[MyMCP.init] Token identifiers',
				{
					hasSchwabUserId: !!this.props.schwabUserId,
					hasClientId: !!this.props.clientId,
					expectedKeyPrefix: sanitizeKeyForLog(kvToken.kvKey(getTokenIds())),
				},
			)

			// Token save function uses KV store exclusively
			// Saves under both schwabUserId (if available) AND stable SCHWAB_CLIENT_ID for reliable reconnection
			const saveTokenForETM = async (tokenSet: TokenData) => {
				const tokenIds = getTokenIds()
				await kvToken.save(tokenIds, tokenSet)

				// Also save under stable SCHWAB_CLIENT_ID for reconnection lookup
				// This ensures tokens can be found even before schwabUserId is known
				const stableTokenIds = {
					clientId: this.validatedConfig.SCHWAB_CLIENT_ID,
				}
				await kvToken.save(stableTokenIds, tokenSet)

				this.mcpLogger.debug('ETM: Token save to KV complete', {
					primaryKey: sanitizeKeyForLog(kvToken.kvKey(tokenIds)),
					stableKey: sanitizeKeyForLog(kvToken.kvKey(stableTokenIds)),
				})
			}

			// Token load function uses KV store exclusively
			const loadTokenForETM = async (): Promise<TokenData | null> => {
				const tokenIds = getTokenIds()
				this.mcpLogger.debug('[ETM Load] Attempting to load token', {
					hasSchwabUserId: !!tokenIds.schwabUserId,
					hasClientId: !!tokenIds.clientId,
					expectedKeyPrefix: sanitizeKeyForLog(kvToken.kvKey(tokenIds)),
				})

				const tokenData = await kvToken.load(tokenIds)
				this.mcpLogger.debug('ETM: Token load from KV complete', {
					keyPrefix: sanitizeKeyForLog(kvToken.kvKey(tokenIds)),
				})
				return tokenData
			}

			this.mcpLogger.debug(
				'[MyMCP.init] STEP 2: Storage and event handlers defined.',
			)

			// 1. Create ETM instance (synchronous)
			const hadExistingTokenManager = !!this.tokenManager
			this.mcpLogger.debug('[MyMCP.init] STEP 3A: ETM instance setup', {
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
			this.mcpLogger.debug('[MyMCP.init] STEP 3B: ETM instance ready', {
				wasReused: hadExistingTokenManager,
			})

			const mcpLogger: SchwabApiLogger = {
				debug: (message: string, ...args: any[]) =>
					this.mcpLogger.debug(message, args.length > 0 ? args[0] : undefined),
				info: (message: string, ...args: any[]) =>
					this.mcpLogger.info(message, args.length > 0 ? args[0] : undefined),
				warn: (message: string, ...args: any[]) =>
					this.mcpLogger.warn(message, args.length > 0 ? args[0] : undefined),
				error: (message: string, ...args: any[]) =>
					this.mcpLogger.error(message, args.length > 0 ? args[0] : undefined),
			}
			this.mcpLogger.debug('[MyMCP.init] STEP 4: MCP Logger adapted.')

			// 2. Proactively initialize ETM to load tokens BEFORE creating client
			this.mcpLogger.debug(
				'[MyMCP.init] STEP 5A: Proactively calling this.tokenManager.initialize() (async)...',
			)
			const etmInitSuccess = this.tokenManager.initialize()
			this.mcpLogger.debug(
				`[MyMCP.init] STEP 5B: Proactive ETM initialization complete. Success: ${etmInitSuccess}`,
			)

			// 2.5. Auto-migrate tokens if we have schwabUserId but token was loaded from clientId key
			if (this.props.schwabUserId && this.props.clientId) {
				await kvToken.migrateIfNeeded(
					{ clientId: this.props.clientId },
					{ schwabUserId: this.props.schwabUserId },
				)
				this.mcpLogger.debug('[MyMCP.init] STEP 5C: Token migration completed')
			}

			// 3. Create SchwabApiClient AFTER tokens are loaded
			this.client = createApiClient({
				config: {
					environment: ENVIRONMENTS.PRODUCTION,
					logger: mcpLogger,
					enableLogging: true,
					logLevel:
						this.validatedConfig.ENVIRONMENT === 'production'
							? 'error'
							: 'debug',
				},
				auth: this.tokenManager,
			})
			this.mcpLogger.debug('[MyMCP.init] STEP 6: SchwabApiClient ready.')
			this.mcpLogger.debug(
				'[MyMCP.init] STEP 7: MyMCP.init FINISHED SUCCESSFULLY',
			)
		} catch (error: any) {
			this.mcpLogger.error(
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
		this.mcpLogger.info('Handling reconnection in MyMCP instance')
		try {
			if (!this.tokenManager) {
				this.mcpLogger.warn(
					'Token manager not initialized, attempting full initialization',
				)
				await this.init()
				return true
			}
			this.mcpLogger.info('Attempting reconnection via token manager')

			try {
				this.mcpLogger.info('Attempting to fetch access token as recovery test')
				const token = await this.tokenManager.getAccessToken()
				if (token) {
					this.mcpLogger.info(
						'Successfully retrieved access token during reconnection',
					)
					return true
				}
			} catch (tokenError) {
				this.mcpLogger.warn('Failed to get access token during reconnection', {
					error:
						tokenError instanceof Error
							? tokenError.message
							: String(tokenError),
				})
			}

			try {
				this.mcpLogger.info(
					'Attempting proactive reinitialization of token manager',
				)
				const initResult = await this.tokenManager.initialize()
				this.mcpLogger.info(
					`Token manager reinitialization ${initResult ? 'succeeded' : 'failed'}`,
				)
				if (initResult) {
					return true
				}
			} catch (initError) {
				this.mcpLogger.warn('Token manager reinitialization failed', {
					error:
						initError instanceof Error ? initError.message : String(initError),
				})
			}

			try {
				this.mcpLogger.info('Token manager state during reconnection', {
					hasTokenManager: !!this.tokenManager,
				})
			} catch (stateError) {
				this.mcpLogger.warn(
					'Failed to check token manager state during reconnection',
					{
						error:
							stateError instanceof Error
								? stateError.message
								: String(stateError),
					},
				)
			}

			this.mcpLogger.warn(
				'Reconnection recovery attempts failed, performing full reinitialization',
			)
			await this.init()
			return true
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			const stack = error instanceof Error ? error.stack : undefined
			this.mcpLogger.error('Critical error during reconnection handling', {
				error: message,
				stack,
			})
			try {
				this.mcpLogger.warn(
					'Attempting emergency reinitialization after reconnection failure',
				)
				await this.init()
				return true
			} catch (initError) {
				const initMessage =
					initError instanceof Error ? initError.message : String(initError)
				this.mcpLogger.error('Emergency reinitialization also failed', {
					error: initMessage,
				})
				return false
			}
		}
	}

	async onSSE(event: any) {
		this.mcpLogger.info('SSE connection established or reconnected')
		// Start idle timeout tracking
		await this.updateActivity()
		await this.onReconnect()
		const response = await super.onSSE(event)
		// Capture transport reference for idle timeout management
		// Access via 'any' since parent's transport is private
		this.sseTransport = (this as any).transport
		return response
	}
}

// Create the OAuth provider for MCP protocol
const oauthProvider = new OAuthProvider({
	apiRoute: API_ENDPOINTS.SSE,
	apiHandler: MyMCP.mount(API_ENDPOINTS.SSE) as any, // Cast remains due to library typing
	defaultHandler: SchwabHandler as any, // Cast remains
	authorizeEndpoint: API_ENDPOINTS.AUTHORIZE,
	tokenEndpoint: API_ENDPOINTS.TOKEN,
	clientRegistrationEndpoint: API_ENDPOINTS.REGISTER,
})

// Export a wrapper that routes /api/* to ApiHandler, everything else to OAuthProvider
export default {
	async fetch(
		request: Request,
		env: Env,
		ctx: ExecutionContext,
	): Promise<Response> {
		const url = new URL(request.url)

		// Route /api/* requests to the direct API handler (bypasses MCP OAuth)
		if (url.pathname.startsWith('/api')) {
			return ApiHandler.fetch(request, env, ctx)
		}

		// All other requests go through OAuthProvider
		return oauthProvider.fetch(request, env, ctx)
	},
}
