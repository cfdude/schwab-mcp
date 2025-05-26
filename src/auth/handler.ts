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
import { AuthError, formatAuthError } from './errorMessages'
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
			const errorInfo = formatAuthError(AuthError.MISSING_CLIENT_ID)
			logger.error(errorInfo.message)
			return c.text('Invalid request', errorInfo.status)
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
		const errorInfo = formatAuthError(AuthError.AUTH_REQUEST_ERROR, { error })
		logger.error(errorInfo.message, { error })
		return c.text(errorInfo.message, errorInfo.status)
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
                const { state, headers } = await parseRedirectApproval(
                        c.req.raw,
                        config,
                )

		if (!state.oauthReqInfo) {
			const errorInfo = formatAuthError(AuthError.MISSING_STATE)
			logger.error(errorInfo.message)
			return c.text('Invalid request', errorInfo.status)
		}

		// Pass the actual AuthRequest object to redirectToSchwab
		const authRequestForSchwab = state.oauthReqInfo

		// Validate required AuthRequest fields before passing to redirectToSchwab
		if (!authRequestForSchwab?.clientId || !authRequestForSchwab?.scope) {
			const errorInfo = formatAuthError(AuthError.INVALID_STATE)
			logger.error(errorInfo.message, {
				missingFields: {
					clientId: !authRequestForSchwab?.clientId,
					scope: !authRequestForSchwab?.scope,
				},
			})
			return c.text('Invalid state information', errorInfo.status)
		}

                return redirectToSchwab(c, config, authRequestForSchwab, headers)
	} catch (error) {
		const errorInfo = formatAuthError(AuthError.AUTH_APPROVAL_ERROR, { error })
		logger.error(errorInfo.message, { error })
		return c.text(errorInfo.message, errorInfo.status)
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
			const errorInfo = formatAuthError(AuthError.MISSING_PARAMETERS, {
				hasState: !!stateParam,
				hasCode: !!code,
			})
			logger.error(errorInfo.message, errorInfo.details)
			return c.text(errorInfo.message, errorInfo.status)
		}

		// Parse the state using our utility function.
		// `decodedStateAsAuthRequest` is the AuthRequest object itself that was sent to Schwab.
                const decodedStateAsAuthRequest = await decodeAndVerifyState(config, stateParam)
		if (!decodedStateAsAuthRequest) {
			const errorInfo = formatAuthError(AuthError.INVALID_STATE)
			logger.error(errorInfo.message)
			return c.text(errorInfo.message, errorInfo.status)
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
			const errorInfo = formatAuthError(AuthError.INVALID_STATE, {
				detail:
					'Decoded state object from Schwab callback is missing required AuthRequest fields (clientId, redirectUri, or scope).',
				decodedState: decodedStateAsAuthRequest, // Log the problematic state
			})
			logger.error(errorInfo.message, errorInfo.details)
			return c.text(errorInfo.message, errorInfo.status)
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
                        const tokenStr = await config.OAUTH_KV?.get(
				`token:${userIdForKV}`,
			)
			return tokenStr ? (JSON.parse(tokenStr) as TokenData) : null
		}

		// Use the validated config for auth client to ensure consistency
                const auth = initializeSchwabAuthClient(config, redirectUri, loadToken, saveToken)

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
			throw new Error(
				`Token exchange failed: ${exchangeError instanceof Error ? exchangeError.message : 'unknown error'}`,
			)
		}

		// Log token information (without sensitive details)
		logger.info('Token exchange successful', {
			hasAccessToken: !!tokenSet?.accessToken,
			hasRefreshToken: !!tokenSet?.refreshToken,
			expiresAt: tokenSet?.expiresAt
				? new Date(tokenSet.expiresAt).toISOString()
				: 'unknown',
		})

		// Create API client
		logger.info('Creating Schwab API client')
		let client
		try {
			client = await createApiClient({
				config: { environment: 'PRODUCTION' },
				auth,
			})
		} catch (clientError) {
			logger.error('Failed to create API client', {
				error: clientError,
				message:
					clientError instanceof Error
						? clientError.message
						: String(clientError),
			})
			throw new Error(
				`API client creation failed: ${clientError instanceof Error ? clientError.message : 'unknown error'}`,
			)
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
			throw new Error(
				`User preferences fetch failed: ${preferencesError instanceof Error ? preferencesError.message : 'unknown error'}`,
			)
		}

		logger.debug('User preferences response', {
			hasPreferences: !!userPreferences,
			hasStreamerInfo: !!userPreferences?.streamerInfo,
			streamerInfoCount: userPreferences?.streamerInfo?.length || 0,
		})

		const userIdFromSchwab =
			userPreferences?.streamerInfo?.[0]?.schwabClientCorrelId

		if (!userIdFromSchwab) {
			const errorInfo = formatAuthError(AuthError.NO_USER_ID)
			logger.error(errorInfo.message)
			return c.text(errorInfo.message, errorInfo.status)
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

		let mcpErrorType = AuthError.AUTH_CALLBACK_ERROR // Default MCP error for this handler
		let detailMessage = error instanceof Error ? error.message : String(error)
		let httpStatus = 500 // Default HTTP status

		if (isSchwabAuthError) {
			const schwabAuthErr = error as SchwabAuthError
			detailMessage = schwabAuthErr.message
			httpStatus = schwabAuthErr.status || 400

			switch (schwabAuthErr.code) {
				case SchwabSDKAuthErrorCode.INVALID_CODE:
				case SchwabSDKAuthErrorCode.PKCE_VERIFIER_MISSING:
					mcpErrorType = AuthError.TOKEN_EXCHANGE_ERROR
					detailMessage = `Token exchange failed: Invalid authorization code or PKCE issue. Details: ${schwabAuthErr.message}`
					break
				case SchwabSDKAuthErrorCode.TOKEN_EXPIRED:
					mcpErrorType = AuthError.TOKEN_EXCHANGE_ERROR
					detailMessage = `Token operation failed: Token expired, re-authentication required. Details: ${schwabAuthErr.message}`
					httpStatus = 401
					break
				case SchwabSDKAuthErrorCode.UNAUTHORIZED:
					mcpErrorType = AuthError.TOKEN_EXCHANGE_ERROR
					detailMessage = `Authorization failed: Client unauthorized or invalid credentials. Details: ${schwabAuthErr.message}`
					httpStatus = schwabAuthErr.status || 401
					break
				case SchwabSDKAuthErrorCode.TOKEN_PERSISTENCE_LOAD_FAILED:
					mcpErrorType = AuthError.AUTH_CALLBACK_ERROR
					detailMessage = `Critical: Failed to load token data during authorization. Details: ${schwabAuthErr.message}`
					httpStatus = 500
					break
				case SchwabSDKAuthErrorCode.TOKEN_PERSISTENCE_SAVE_FAILED:
					mcpErrorType = AuthError.AUTH_CALLBACK_ERROR
					detailMessage = `Critical: Failed to save token data during authorization. Details: ${schwabAuthErr.message}`
					httpStatus = 500
					break
				case SchwabSDKAuthErrorCode.TOKEN_VALIDATION_ERROR:
					mcpErrorType = AuthError.AUTH_CALLBACK_ERROR
					detailMessage = `Critical: Token validation failed during authorization. Details: ${schwabAuthErr.message}`
					httpStatus = 500
					break
				case SchwabSDKAuthErrorCode.TOKEN_ENDPOINT_CONFIG_ERROR:
					mcpErrorType = AuthError.AUTH_CALLBACK_ERROR
					detailMessage = `Critical: Auth system configuration error. Details: ${schwabAuthErr.message}`
					httpStatus = 500
					break
				case SchwabSDKAuthErrorCode.REFRESH_NEEDED:
					mcpErrorType = AuthError.API_RESPONSE_ERROR
					detailMessage = `Failed to refresh token during API call: ${schwabAuthErr.message}`
					httpStatus = schwabAuthErr.status || 500
					break
				default:
					mcpErrorType = AuthError.AUTH_CALLBACK_ERROR
					detailMessage = `An authentication error occurred: ${schwabAuthErr.message}`
					break
			}
		} else if (isSchwabApiErrorInstance) {
			const schwabApiErr = error as SchwabApiError
			mcpErrorType = AuthError.API_RESPONSE_ERROR
			detailMessage = `API request failed during authorization: ${schwabApiErr.message}`
			httpStatus = schwabApiErr.status || 500
		}

		const errorInfo = formatAuthError(mcpErrorType, {
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
			mcpErrorType,
		})

		return c.text(
			`Authorization failed: ${errorInfo.message}`,
			errorInfo.status,
		)
	}
})

export { app as SchwabHandler }
