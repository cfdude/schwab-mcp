import {
	type OAuthHelpers,
	type AuthRequest,
} from '@cloudflare/workers-oauth-provider'
import {
	createSchwabAuth as SchwabAuthCreatorFromLibrary,
	AuthStrategy,
	type TokenData,
	type EnhancedTokenManager,
	type EnhancedTokenManagerOptions,
	encodeOAuthState,
} from '@sudowealth/schwab-api'
import { type Context } from 'hono'
import { type BlankInput } from 'hono/types'
import { type ValidatedEnv, type Env } from '../../types/env'
import { LOGGER_CONTEXTS } from '../shared/constants'
import { logger } from '../shared/log'
import { AuthErrors, formatAuthError } from './errors'
import { mapTokenPersistence } from './tokenPersistence'

// Create scoped logger for auth client
const authLogger = logger.child(LOGGER_CONTEXTS.AUTH_CLIENT)

/**
 * Creates a Schwab Auth client with enhanced features
 *
 * @param redirectUri OAuth callback URI
 * @param load Function to load tokens from storage
 * @param save Function to save tokens to storage
 * @returns Initialized Schwab auth client as EnhancedTokenManager
 */
export function initializeSchwabAuthClient(
	config: ValidatedEnv,
	redirectUri = config.SCHWAB_REDIRECT_URI,
	load?: () => Promise<TokenData | null>,
	save?: (tokenData: TokenData) => Promise<void>,
): EnhancedTokenManager {
	const clientId = config.SCHWAB_CLIENT_ID
	const clientSecret = config.SCHWAB_CLIENT_SECRET

	authLogger.debug('Using centralized environment for Schwab Auth client')

	authLogger.info('Initializing enhanced Schwab Auth client', {
		hasLoadFunction: !!load,
		hasSaveFunction: !!save,
	})

	// Map our load/save functions to what EnhancedTokenManager expects
	const { load: mappedLoad, save: mappedSave } = mapTokenPersistence(load, save)

	// Build options for EnhancedTokenManager with MCP-specific defaults
	const tokenManagerOptions: EnhancedTokenManagerOptions = {
		clientId,
		clientSecret,
		redirectUri,
		load: mappedLoad,
		save: mappedSave,
		validateTokens: true,
		autoReconnect: true,
		debug: config.LOG_LEVEL === 'debug' || config.LOG_LEVEL === 'trace',
		traceOperations: config.LOG_LEVEL === 'trace',
		// 7 min — MUST exceed the CLIENT's authlib leeway (300s in schwab-py: personal-finance
		// schwab/auth.py). At exactly 300s the token manager would serve a cached token that the
		// client considers already-expired (authlib InvalidTokenError → a weekly false
		// "re-authenticate" alarm). Refreshing above the leeway guarantees a vended token is always
		// usable client-side. See personal-finance change schwab-token-expiry-false-positive.
		refreshThresholdMs: 7 * 60 * 1000,
	}

	// Configure auth with enhanced token manager
	const authConfig = {
		strategy: AuthStrategy.ENHANCED,
		oauthConfig: tokenManagerOptions,
	}

	const authClient = SchwabAuthCreatorFromLibrary(authConfig)
	return authClient
}

/**
 * Redirects the user to Schwab's authorization page
 *
 * @param c Hono context
 * @param config Validated environment configuration
 * @param oauthReqInfo OAuth request information
 * @param headers Optional headers to include in the response
 * @returns Redirect response to Schwab's authorization page
 */
export async function redirectToSchwab(
	c: Context<
		{
			Bindings: Env & {
				OAUTH_PROVIDER: OAuthHelpers
			}
		},
		'/authorize',
		BlankInput
	>,
	config: ValidatedEnv,
	oauthReqInfo: AuthRequest,
	headers: HeadersInit = {},
): Promise<Response> {
	try {
		const auth = initializeSchwabAuthClient(config)

		// Use SDK's OAuth state encoder
		const encodedState = encodeOAuthState(oauthReqInfo)
		const { authUrl } = await auth.getAuthorizationUrl({
			state: encodedState,
		})

		// Create redirect response with any additional headers
		if (Object.keys(headers).length > 0) {
			return new Response(null, {
				status: 302,
				headers: {
					Location: authUrl,
					...headers,
				},
			})
		} else {
			return Response.redirect(authUrl, 302)
		}
	} catch (error) {
		const authError = new AuthErrors.AuthUrl(
			error instanceof Error ? error : undefined,
		)
		const errorInfo = formatAuthError(authError, { error })
		authLogger.error(errorInfo.message, { error })
		return new Response(errorInfo.message, { status: errorInfo.status })
	}
}
