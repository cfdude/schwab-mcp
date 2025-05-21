import OAuthProvider from '@cloudflare/workers-oauth-provider'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	createApiClient,
	type SchwabApiClient,
	type EnhancedTokenManager,
	type SchwabApiLogger,
} from '@sudowealth/schwab-api'
import { DurableMCP } from 'workers-mcp'
import { z } from 'zod'
import {
	SchwabHandler,
	initializeTokenManager,
	type CodeFlowTokenData,
	initializeSchwabAuthClient,
} from './auth'
import { type ITokenManager } from './auth/tokenInterface'
import { TokenStateMachine } from './auth/tokenStateMachine'
import { getEnvironment, initializeEnvironment } from './config'
import { logger } from './shared/logger'
import { toolRegistry, toolError, formatResponse } from './shared/toolBuilder'
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
} from './tools'
import { type ValidatedEnv } from './types/env'

type Props = {
	accessToken: string
	refreshToken: string
	expiresAt: number
}

export class MyMCP extends DurableMCP<Props, Env> {
	private tokenManager!: EnhancedTokenManager
	private centralTokenManager!: ITokenManager
	private client!: SchwabApiClient
	private validatedConfig!: ValidatedEnv

	server = new McpServer({
		name: 'Schwab MCP',
		version: '0.0.1',
	})

	async init() {
		try {
			logger.info('Initializing Schwab MCP server')
			this.validatedConfig = initializeEnvironment(this.env)
			const redirectUri = this.validatedConfig.SCHWAB_REDIRECT_URI

			if (this.tokenManager && this.client && this.centralTokenManager) {
				logger.info(
					'Auth components already exist, skipping recreation during init',
				)
			} else {
				logger.info('Creating auth components')
				const saveToken = async (tokens: CodeFlowTokenData) => {
					if (tokens.accessToken) this.props.accessToken = tokens.accessToken
					if (tokens.refreshToken) this.props.refreshToken = tokens.refreshToken
					if (tokens.expiresAt) this.props.expiresAt = tokens.expiresAt
					this.props = { ...this.props }
					logger.info('Token save operation', {
						hasAccessToken: !!tokens.accessToken,
						hasRefreshToken: !!tokens.refreshToken,
						expiresAt: tokens.expiresAt
							? new Date(tokens.expiresAt).toISOString()
							: 'unknown',
					})
				}
				const loadToken = async () => {
					if (
						this.props.accessToken &&
						this.props.refreshToken &&
						this.props.expiresAt
					) {
						const tokenData = {
							accessToken: this.props.accessToken,
							refreshToken: this.props.refreshToken,
							expiresAt: this.props.expiresAt,
						}
						logger.info('Token load operation', {
							hasAccessToken: !!tokenData.accessToken,
							hasRefreshToken: !!tokenData.refreshToken,
							expiresAt: tokenData.expiresAt
								? new Date(tokenData.expiresAt).toISOString()
								: 'unknown',
						})
						return tokenData
					}
					logger.info('No token data available during load operation')
					return null
				}
				try {
					logger.info('Initializing Schwab auth client')
					this.tokenManager = initializeSchwabAuthClient(
						redirectUri,
						loadToken,
						saveToken,
					)
					logger.info('Schwab auth client initialized successfully')
				} catch (initError) {
					const message =
						initError instanceof Error ? initError.message : String(initError)
					logger.error('Failed to initialize Schwab auth client', {
						error: message,
					})
					throw new Error(
						`Schwab auth client initialization failed: ${message}`,
					)
				}
				logger.info('Creating TokenStateMachine for token management')
				try {
					this.centralTokenManager = new TokenStateMachine(this.tokenManager)
					logger.info('TokenStateMachine created successfully')
					logger.info('Performing TokenStateMachine initialization')
					const initSuccess = await (
						this.centralTokenManager as TokenStateMachine
					).initialize?.() // Added optional chaining and cast for initialize
					logger.info(
						`TokenStateMachine initialization ${initSuccess ? 'succeeded' : 'partial or failed'}`,
						{
							initSuccess,
							tokenManagerState: (this.centralTokenManager as TokenStateMachine)
								.getDiagnostics
								? (
										await (
											this.centralTokenManager as TokenStateMachine
										).getDiagnostics()
									).stateMachineStatus
								: 'unknown',
						},
					)
				} catch (tokenMachineError) {
					const message =
						tokenMachineError instanceof Error
							? tokenMachineError.message
							: String(tokenMachineError)
					logger.error('Failed to create or initialize TokenStateMachine', {
						error: message,
					})
					throw new Error(`TokenStateMachine initialization failed: ${message}`)
				}
				logger.info('Registering TokenStateMachine with singleton registry')
				initializeTokenManager(this.centralTokenManager)
				const mcpLogger = logger
				const adaptedLogger: SchwabApiLogger = {
					debug: (message: string, ...args: any[]) =>
						mcpLogger.debug(message, args.length > 0 ? args[0] : undefined),
					info: (message: string, ...args: any[]) =>
						mcpLogger.info(message, args.length > 0 ? args[0] : undefined),
					warn: (message: string, ...args: any[]) =>
						mcpLogger.warn(message, args.length > 0 ? args[0] : undefined),
					error: (message: string, ...args: any[]) =>
						mcpLogger.error(message, args.length > 0 ? args[0] : undefined),
				}
				this.client = await createApiClient({
					config: {
						environment: 'PRODUCTION',
						logger: adaptedLogger,
						enableLogging: true,
						logLevel: 'debug',
					},
					auth: this.tokenManager,
				})
			}
			if (!this.centralTokenManager) {
				logger.warn('Token manager not found during initialization')
			}
			await this.registerTools(this.client)
			logger.info(
				'[MyMCP] Initialization complete. McpServer tools should be registered.',
			)
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			logger.error('Error during initialization', {
				error: message,
				stack: error instanceof Error ? error.stack : undefined,
			})
			throw error
		}
	}

	private async registerTools(client: SchwabApiClient) {
		logger.info('[MyMCP] Starting specific tool registration...')
		registerAccountTools(client, this.server)
		registerInstrumentTools(client, this.server)
		registerMarketHoursTools(client, this.server)
		registerMoversTools(client, this.server)
		registerOptionsTools(client, this.server)
		registerOrderTools(client, this.server)
		registerPriceHistoryTools(client, this.server)
		registerQuotesTools(client, this.server)
		registerTransactionTools(client, this.server)
		logger.info(
			'[MyMCP] Finished specific tool registration. Internal toolRegistry should be populated.',
		)

		// Define the schema for the generic dispatcher's input
		const dispatchToolSchema = z.object({
			toolName: z
				.string()
				.describe("The actual tool to call (e.g., 'getAccounts')"),
			toolArgs: z.any().optional().describe('Arguments for the specified tool'),
		})

		// Register the generic dispatcher tool
		const dispatcherToolName = 'call' // This should match what the client invokes, likely without "tools/"
		logger.info(
			`[MyMCP] Attempting to register generic dispatcher tool as '${dispatcherToolName}'.`,
		)
		this.server.tool(
			dispatcherToolName,
			dispatchToolSchema.shape,
			async (input: z.infer<typeof dispatchToolSchema>) => {
				const { toolName, toolArgs } = input
				logger.info(`[MCP Dispatcher] Received call for tool: '${toolName}'`, {
					args: toolArgs,
				})

				const registeredTool = toolRegistry.get(toolName)

				if (!registeredTool) {
					logger.error(
						`[MCP Dispatcher] Tool not found in registry: '${toolName}'`,
					)
					return formatResponse(
						toolError(`Tool '${toolName}' not found.`, {
							availableTools: Array.from(toolRegistry.keys()),
							requestedTool: toolName,
						}),
					)
				}

				try {
					const argsToParse =
						toolArgs === undefined &&
						registeredTool.schema.safeParse(undefined).success
							? undefined
							: toolArgs || {}
					const validatedArgs = registeredTool.schema.parse(argsToParse)

					logger.debug(
						`[MCP Dispatcher] Executing '${toolName}' with validated args.`,
						{ validatedArgs },
					)
					const result = await registeredTool.handler(
						validatedArgs,
						this.client,
					)

					if (result && result.content && Array.isArray(result.content)) {
						return result
					}
					return formatResponse(result)
				} catch (e) {
					const errMessage = e instanceof Error ? e.message : String(e)
					logger.error(
						`[MCP Dispatcher] Error executing tool '${toolName}' or validating its arguments.`,
						{ error: errMessage, toolArgs },
					)
					if (e instanceof z.ZodError) {
						return formatResponse(
							toolError(`Invalid arguments for tool '${toolName}'.`, {
								validationErrors: e.format(),
								toolName,
							}),
						)
					}
					return formatResponse(
						toolError(e instanceof Error ? e : new Error(errMessage), {
							toolBeingCalled: toolName,
							step: 'execution',
						}),
					)
				}
			},
		)
		logger.info(
			`[MyMCP] Registered generic dispatcher tool as '${dispatcherToolName}'.`,
		)
		logger.info(
			'[MyMCP] All tool registration functions executed successfully.',
		)
	}

	async onReconnect() {
		logger.info('Handling reconnection in MyMCP instance')
		try {
			if (!this.centralTokenManager) {
				logger.warn(
					'TokenStateMachine not initialized, attempting full initialization',
				)
				await this.init()
				return true
			}
			logger.info('Attempting reconnection via TokenStateMachine')
			let tokenManagerState = 'unknown'
			if (
				this.centralTokenManager instanceof TokenStateMachine &&
				this.centralTokenManager.getDiagnostics
			) {
				const diagnostics = await this.centralTokenManager.getDiagnostics()
				tokenManagerState = (diagnostics as any)?.state || 'unknown'
			}
			logger.debug('Current token manager state before reconnection', {
				tokenManagerState,
			})

			const reconnectSuccess =
				await this.centralTokenManager.handleReconnection()

			if (reconnectSuccess) {
				let newState = 'unknown'
				if (
					this.centralTokenManager instanceof TokenStateMachine &&
					this.centralTokenManager.getDiagnostics
				) {
					const diagnostics = await this.centralTokenManager.getDiagnostics()
					newState = (diagnostics as any)?.state || 'unknown'
				}
				logger.info('TokenStateMachine reconnection successful', { newState })
				return true
			}
			logger.warn(
				'Standard reconnection handling failed, attempting phased recovery',
			)
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
			try {
				logger.info('Attempting to fetch access token as recovery test')
				const token = await this.centralTokenManager.getAccessToken()
				if (token) {
					logger.info('Successfully retrieved access token during recovery')
					return true
				}
			} catch (tokenError) {
				logger.warn('Failed to get access token during recovery', {
					error:
						tokenError instanceof Error
							? tokenError.message
							: String(tokenError),
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
			hasTokenManager: !!this.centralTokenManager,
			hasTokenClient: !!this.tokenManager,
			hasClient: !!this.client,
			implementationType: this.centralTokenManager
				? this.centralTokenManager.constructor.name
				: 'undefined',
		}
		try {
			const env = getEnvironment()
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
		if (
			this.centralTokenManager instanceof TokenStateMachine &&
			this.centralTokenManager.getDiagnostics
		) {
			try {
				const tokenStateDiag = await this.centralTokenManager.getDiagnostics()
				diagnosticInfo.tokenStateMachine = tokenStateDiag // Changed key to avoid conflict
				if (tokenStateDiag && typeof tokenStateDiag === 'object') {
					diagnosticInfo.tokenStatus = {
						// Keep this for high-level summary
						state: (tokenStateDiag as any).state || 'unknown',
						hasValidAccessToken:
							(tokenStateDiag as any).hasAccessToken &&
							(tokenStateDiag as any).expiresIn > 0,
						hasExpiredAccessToken:
							(tokenStateDiag as any).hasAccessToken &&
							(tokenStateDiag as any).expiresIn <= 0,
						hasRefreshToken: (tokenStateDiag as any).hasRefreshToken,
						expiresInSeconds: (tokenStateDiag as any).expiresIn,
						lastReconnection: (tokenStateDiag as any).lastReconnection,
					}
				}
			} catch (tsDiagError) {
				diagnosticInfo.tokenStateDiagnosticError =
					tsDiagError instanceof Error
						? tsDiagError.message
						: String(tsDiagError)
			}
		}
		if (this.tokenManager) {
			try {
				// Ensure EnhancedTokenManager methods are checked correctly
				if (
					typeof (this.tokenManager as EnhancedTokenManager).getDiagnostics ===
					'function'
				) {
					diagnosticInfo.enhancedTokenManager = await (
						this.tokenManager as EnhancedTokenManager
					).getDiagnostics()
				} else if (
					typeof (this.tokenManager as EnhancedTokenManager)
						.generateTokenReport === 'function'
				) {
					diagnosticInfo.enhancedTokenManager = await (
						this.tokenManager as EnhancedTokenManager
					).generateTokenReport()
				}
			} catch (etmDiagError) {
				diagnosticInfo.enhancedTokenManagerDiagnosticError =
					etmDiagError instanceof Error
						? etmDiagError.message
						: String(etmDiagError)
			}
		}
		logger.info('Diagnostic information gathered', {
			timestamp: diagnosticInfo.timestamp,
			tokenStatusState: diagnosticInfo.tokenStatus?.state, // Log specific part for brevity
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
