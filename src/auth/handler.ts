import { type OAuthHelpers } from '@cloudflare/workers-oauth-provider'
import {
	createApiClient,
	SchwabAuthError,
	SchwabApiError,
	AuthErrorCode as SchwabSDKAuthErrorCode,
	type TokenData,
} from '@sudowealth/schwab-api'
import { Hono } from 'hono'
import { buildConfig } from '../config'
import { logger } from '../shared/logger'
import { type Env } from '../types/env'
import { initializeSchwabAuthClient, redirectToSchwab } from './client'
import { clientIdAlreadyApproved, parseRedirectApproval } from './cookies'
import {
	MissingClientIdError,
	MissingStateError,
	MissingParametersError,
	InvalidStateError,
	AuthRequestError,
	AuthApprovalError,
	AuthCallbackError,
	NoUserIdError,
	TokenExchangeError,
	ApiResponseError,
	formatAuthError,
} from './errors'
import { ensureEnvInitialized } from './middlewares'
import { decodeAndVerifyState, extractClientIdFromState } from './stateUtils'
import { renderApprovalDialog } from './ui'

// Create Hono app with appropriate bindings
const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>()

// No need to store config locally, we'll build it per request

/**
 * GET /authorize - Entry point for OAuth authorization flow
 *
 * This endpoint checks if the client is already approved, and either:
 * 1. Redirects directly to Schwab if approved
 * 2. Shows an approval dialog if not approved
 */
app.get('/authorize', async (c) => {
	try {
		const config = buildConfig(c.env)
		const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw)
		const { clientId } = oauthReqInfo

		if (!clientId) {
			const error = new MissingClientIdError()
			const errorInfo = formatAuthError(error)
			logger.error(errorInfo.message)
			return c.text('Invalid request', errorInfo.status as any)
		}

		// If client ID is already approved, redirect directly to Schwab
		if (
			await clientIdAlreadyApproved(
				c.req.raw,
				oauthReqInfo.clientId,
				config.COOKIE_ENCRYPTION_KEY,
			)
		) {
			return redirectToSchwab(c, config, oauthReqInfo)
		}

		// Otherwise, render the approval dialog
		return renderApprovalDialog(c.req.raw, {
			client: await c.env.OAUTH_PROVIDER.lookupClient(clientId),
			server: {
				name: 'Schwab MCP Server',
				description:
					'Access your Schwab accounts and market data in MCP clients.',
			},
			state: { oauthReqInfo },
		})
	} catch (error) {
		const authError = new AuthRequestError()
		const errorInfo = formatAuthError(authError, { error })
		logger.error(errorInfo.message, { error })
		return c.text(errorInfo.message, errorInfo.status as any)
	}
})

/**
 * POST /authorize - Handle approval dialog submission
 *
 * After the user approves the request, this endpoint processes the form submission
 * and redirects to Schwab for authentication
 */
app.post('/authorize', async (c) => {
	try {
		const config = buildConfig(c.env)
		const { state, headers } = await parseRedirectApproval(c.req.raw, config)

		if (!state.oauthReqInfo) {
			const error = new MissingStateError()
			const errorInfo = formatAuthError(error)
			logger.error(errorInfo.message)
			return c.text('Invalid request', errorInfo.status as any)
		}

		// Pass the actual AuthRequest object to redirectToSchwab
		const authRequestForSchwab = state.oauthReqInfo

		// Validate required AuthRequest fields before passing to redirectToSchwab
		if (!authRequestForSchwab?.clientId || !authRequestForSchwab?.scope) {
			const error = new InvalidStateError()
			const errorInfo = formatAuthError(error, {
				missingFields: {
					clientId: !authRequestForSchwab?.clientId,
					scope: !authRequestForSchwab?.scope,
				},
			})
			logger.error(errorInfo.message, errorInfo.details)
			return c.text('Invalid state information', errorInfo.status as any)
		}

		return redirectToSchwab(c, config, authRequestForSchwab, headers)
	} catch (error) {
		const authError = new AuthApprovalError()
		const errorInfo = formatAuthError(authError, { error })
		logger.error(errorInfo.message, { error })
		return c.text(errorInfo.message, errorInfo.status as any)
	}
})

/**
 * OAuth Callback Endpoint
 *
 * This route handles the callback from Schwab after user authentication.
 * It exchanges the temporary code for an access token and completes the
 * authorization flow.
 */
app.get('/callback', async (c) => {
	try {
		const config = buildConfig(c.env)
		// Extract state and code from query parameters
		const stateParam = c.req.query('state')
		const code = c.req.query('code')

		if (!stateParam || !code) {
			const error = new MissingParametersError()
			const errorInfo = formatAuthError(error, {
				hasState: !!stateParam,
				hasCode: !!code,
			})
			logger.error(errorInfo.message, errorInfo.details)
			return c.text(errorInfo.message, errorInfo.status as any)
		}

		// Parse the state using our utility function.
		// `decodedStateAsAuthRequest` is the AuthRequest object itself that was sent to Schwab.
		const decodedStateAsAuthRequest = await decodeAndVerifyState(
			config,
			stateParam,
		)
		if (!decodedStateAsAuthRequest) {
			const error = new InvalidStateError()
			const errorInfo = formatAuthError(error)
			logger.error(errorInfo.message)
			return c.text(errorInfo.message, errorInfo.status as any)
		}

		// `extractClientIdFromState` will correctly get `decodedStateAsAuthRequest.clientId`.
		// This also serves as validation that clientId exists within the decoded state.
		const clientIdFromState = extractClientIdFromState(
			decodedStateAsAuthRequest,
		)

		// Validate required AuthRequest fields directly on `decodedStateAsAuthRequest`
		if (
			!decodedStateAsAuthRequest?.clientId || // Should be redundant due to extractClientIdFromState
			!decodedStateAsAuthRequest?.redirectUri ||
			!decodedStateAsAuthRequest?.scope
		) {
			const error = new InvalidStateError()
			const errorInfo = formatAuthError(error, {
				detail:
					'Decoded state object from Schwab callback is missing required AuthRequest fields (clientId, redirectUri, or scope).',
				decodedState: decodedStateAsAuthRequest, // Log the problematic state
			})
			logger.error(errorInfo.message, errorInfo.details)
			return c.text(errorInfo.message, errorInfo.status as any)
		}

		// Set up redirect URI and token storage for KV
		const redirectUri = config.SCHWAB_REDIRECT_URI
		const userIdForKV = clientIdFromState // Use the validated clientId for KV key consistency

		const saveToken = async (tokenData: TokenData) => {
			await config.OAUTH_KV?.put(
				`token:${userIdForKV}`,
				JSON.stringify(tokenData),
			)
		}

		const loadToken = async (): Promise<TokenData | null> => {
			const tokenStr = await config.OAUTH_KV?.get(`token:${userIdForKV}`)
			return tokenStr ? (JSON.parse(tokenStr) as TokenData) : null
		}

		// Use the validated config for auth client to ensure consistency
		const auth = initializeSchwabAuthClient(
			config,
			redirectUri,
			loadToken,
			saveToken,
		)

		// Exchange the code for tokens with enhanced error handling
		logger.info(
			'Exchanging authorization code for tokens with state parameter for PKCE',
		)
		let tokenSet
		try {
			// Pass the stateParam directly to EnhancedTokenManager.exchangeCode
			// EnhancedTokenManager will handle extracting the code_verifier from it
			tokenSet = await auth.exchangeCode(code, stateParam)
		} catch (exchangeError) {
			logger.error('Token exchange failed', {
				error: exchangeError,
				message:
					exchangeError instanceof Error
						? exchangeError.message
						: String(exchangeError),
			})
			throw new TokenExchangeError()
		}

		// Log token information (without sensitive details)
		logger.info('Token exchange successful', {
			hasAccessToken: !!tokenSet?.accessToken,
			hasRefreshToken: !!tokenSet?.refreshToken,
			expiresAt: tokenSet?.expiresAt
				? new Date(tokenSet.expiresAt).toISOString()
				: 'unknown',
		})

		// Create (or reuse) API client
		logger.info('Creating Schwab API client')
		let client
		try {
			client =
				globalThis.__schwabClient ??
				(globalThis.__schwabClient = createApiClient({
					config: { environment: 'PRODUCTION' },
					auth,
				}))
		} catch (clientError) {
			logger.error('Failed to create API client', {
				error: clientError,
				message:
					clientError instanceof Error
						? clientError.message
						: String(clientError),
			})
			throw new AuthCallbackError()
		}

		// Fetch user info to get the Schwab user ID
		logger.info('Fetching user preferences to get Schwab user ID')
		let userPreferences
		try {
			userPreferences = await client.trader.userPreference.getUserPreference()
		} catch (preferencesError) {
			logger.error('Failed to fetch user preferences', {
				error: preferencesError,
				message:
					preferencesError instanceof Error
						? preferencesError.message
						: String(preferencesError),
			})
			throw new NoUserIdError()
		}

		logger.debug('User preferences response', {
			hasPreferences: !!userPreferences,
			hasStreamerInfo: !!userPreferences?.streamerInfo,
			streamerInfoCount: userPreferences?.streamerInfo?.length || 0,
		})

		const userIdFromSchwab =
			userPreferences?.streamerInfo?.[0]?.schwabClientCorrelId

		if (!userIdFromSchwab) {
			const error = new NoUserIdError()
			const errorInfo = formatAuthError(error)
			logger.error(errorInfo.message)
			return c.text(errorInfo.message, errorInfo.status as any)
		}

		// Complete the authorization flow using the decoded AuthRequest object
		const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
			request: decodedStateAsAuthRequest,
			userId: userIdFromSchwab,
			metadata: { label: userIdFromSchwab },
			scope: decodedStateAsAuthRequest.scope,
			props: {
				userId: userIdFromSchwab,
				accessToken: tokenSet.accessToken,
				refreshToken: tokenSet.refreshToken,
				expiresAt: tokenSet.expiresAt,
			},
		})

		return Response.redirect(redirectTo)
	} catch (error) {
		const isSchwabAuthError = error instanceof SchwabAuthError
		const isSchwabApiErrorInstance = error instanceof SchwabApiError

		let mcpError = new AuthCallbackError() // Default MCP error for this handler
		let detailMessage = error instanceof Error ? error.message : String(error)
		let httpStatus = 500 // Default HTTP status

		if (isSchwabAuthError) {
			const schwabAuthErr = error as SchwabAuthError
			detailMessage = schwabAuthErr.message
			httpStatus = schwabAuthErr.status || 400

			switch (schwabAuthErr.code) {
				case SchwabSDKAuthErrorCode.INVALID_CODE:
				case SchwabSDKAuthErrorCode.PKCE_VERIFIER_MISSING:
					mcpError = new TokenExchangeError()
					detailMessage = `Token exchange failed: Invalid authorization code or PKCE issue. Details: ${schwabAuthErr.message}`
					break
				case SchwabSDKAuthErrorCode.TOKEN_EXPIRED:
					mcpError = new TokenExchangeError()
					detailMessage = `Token operation failed: Token expired, re-authentication required. Details: ${schwabAuthErr.message}`
					httpStatus = 401
					break
				case SchwabSDKAuthErrorCode.UNAUTHORIZED:
					mcpError = new TokenExchangeError()
					detailMessage = `Authorization failed: Client unauthorized or invalid credentials. Details: ${schwabAuthErr.message}`
					httpStatus = schwabAuthErr.status || 401
					break
				case SchwabSDKAuthErrorCode.TOKEN_PERSISTENCE_LOAD_FAILED:
					mcpError = new AuthCallbackError()
					detailMessage = `Critical: Failed to load token data during authorization. Details: ${schwabAuthErr.message}`
					httpStatus = 500
					break
				case SchwabSDKAuthErrorCode.TOKEN_PERSISTENCE_SAVE_FAILED:
					mcpError = new AuthCallbackError()
					detailMessage = `Critical: Failed to save token data during authorization. Details: ${schwabAuthErr.message}`
					httpStatus = 500
					break
				case SchwabSDKAuthErrorCode.TOKEN_VALIDATION_ERROR:
					mcpError = new AuthCallbackError()
					detailMessage = `Critical: Token validation failed during authorization. Details: ${schwabAuthErr.message}`
					httpStatus = 500
					break
				case SchwabSDKAuthErrorCode.TOKEN_ENDPOINT_CONFIG_ERROR:
					mcpError = new AuthCallbackError()
					detailMessage = `Critical: Auth system configuration error. Details: ${schwabAuthErr.message}`
					httpStatus = 500
					break
				case SchwabSDKAuthErrorCode.REFRESH_NEEDED:
					mcpError = new ApiResponseError()
					detailMessage = `Failed to refresh token during API call: ${schwabAuthErr.message}`
					httpStatus = schwabAuthErr.status || 500
					break
				default:
					mcpError = new AuthCallbackError()
					detailMessage = `An authentication error occurred: ${schwabAuthErr.message}`
					break
			}
		} else if (isSchwabApiErrorInstance) {
			const schwabApiErr = error as SchwabApiError
			mcpError = new ApiResponseError()
			detailMessage = `API request failed during authorization: ${schwabApiErr.message}`
			httpStatus = schwabApiErr.status || 500
		}

		const errorInfo = formatAuthError(mcpError, {
			error,
			sdkErrorMessage: detailMessage,
			sdkErrorCode: isSchwabAuthError
				? (error as SchwabAuthError).code
				: isSchwabApiErrorInstance
					? (error as SchwabApiError).code
					: undefined,
			sdkStatus: httpStatus,
			url: (error as any).config?.url,
			stack: error instanceof Error ? error.stack : undefined,
		})

		logger.error(`Auth callback failed: ${errorInfo.message}`, {
			...errorInfo.details,
			errorType: mcpError.constructor.name,
		})

		return c.text(
			`Authorization failed: ${errorInfo.message}`,
			errorInfo.status as any,
		)
	}
})

export { app as SchwabHandler }
