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
} from '@sudowealth/schwab-api'
import { type Context } from 'hono'
import { type BlankInput } from 'hono/types'
import { getEnvironment } from '../config'
import { logger } from '../shared/logger'
import { type Env } from '../types/env'
import { AuthError, formatAuthError } from './errorMessages'

/**
 * Token data structure required by Schwab enhanced authentication strategy
 */
export interface CodeFlowTokenData extends TokenData {
	accessToken: string
	refreshToken: string
	expiresAt: number
}

/**
 * Event emitted during token lifecycle events
 */
export interface TokenLifecycleEvent {
	type: 'save' | 'load' | 'refresh' | 'expire' | 'error'
	tokenData?: TokenData | null
	error?: Error | null
	timestamp: number
}

/**
 * Result of token validation operations
 */
export interface TokenValidationResult {
	valid: boolean
	canRefresh: boolean
	tokenData?: TokenData | null
	reason?: string
}

/**
 * Result of token refresh operations
 */
export interface TokenRefreshResult {
	success: boolean
	tokenData?: TokenData | null
	error?: Error | null
}

/**
 * Result of reconnection operations
 */
export interface ReconnectionResult {
	success: boolean
	tokenRestored: boolean
	refreshPerformed: boolean
	error?: Error | null
	tokenData?: CodeFlowTokenData
}

/**
 * Creates a Schwab Auth client with enhanced features
 *
 * @param redirectUri OAuth callback URI
 * @param load Function to load tokens from storage
 * @param save Function to save tokens to storage
 * @returns Initialized Schwab auth client as EnhancedTokenManager
 */
export function initializeSchwabAuthClient(
	redirectUri: string,
	load?: () => Promise<CodeFlowTokenData | null>,
	save?: (tokenData: CodeFlowTokenData) => Promise<void>,
): EnhancedTokenManager {
	// Get credentials directly from the centralized environment
	const env = getEnvironment()
	const clientId = env.SCHWAB_CLIENT_ID
	const clientSecret = env.SCHWAB_CLIENT_SECRET

	logger.debug('Using centralized environment for Schwab Auth client')

	logger.info('Initializing enhanced Schwab Auth client', {
		hasLoadFunction: !!load,
		hasSaveFunction: !!save,
	})

	// Map our load/save functions to what EnhancedTokenManager expects
	const mappedLoad = load
		? async () => {
				const mcpToken = await load()
				if (!mcpToken) return null
				return {
					// Map to schwab-api's TokenSet
					accessToken: mcpToken.accessToken,
					refreshToken: mcpToken.refreshToken,
					expiresAt: mcpToken.expiresAt,
				}
			}
		: undefined

	const mappedSave = save
		? async (apiTokenSet: TokenData) => {
				await save({
					// Map from schwab-api's TokenData/TokenSet
					accessToken: apiTokenSet.accessToken,
					refreshToken: apiTokenSet.refreshToken || '', // ensure not undefined
					expiresAt: apiTokenSet.expiresAt || 0, // ensure not undefined
				})
			}
		: undefined

	// Build options for EnhancedTokenManager with MCP-specific defaults
	const tokenManagerOptions: EnhancedTokenManagerOptions = {
		clientId,
		clientSecret,
		redirectUri,
		load: mappedLoad,
		save: mappedSave,
		// MCP-specific desired defaults for EnhancedTokenManager
		validateTokens: true, // Validate tokens on load/use
		autoReconnect: true, // Enable auto reconnection
		debug: true, // Enable debug logging
		traceOperations: true, // Enable operation tracing
		refreshThresholdMs: 5 * 60 * 1000, // 5 minutes before expiration
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
	oauthReqInfo: AuthRequest,
	headers: HeadersInit = {},
): Promise<Response> {
	try {
		// Use the configured redirect URI from environment
		const redirectUri = getEnvironment().SCHWAB_REDIRECT_URI
		const auth = initializeSchwabAuthClient(redirectUri)

		// Get the authorization URL with state parameter
		// Create a custom URL with state parameter since EnhancedTokenManager doesn't support it directly
		const { authUrl: baseAuthUrl } = auth.getAuthorizationUrl({
			// scope is the only property allowed in the options
		})

		// Manually add the state parameter to the URL
		const authUrlObj = new URL(baseAuthUrl)
		authUrlObj.searchParams.append('state', btoa(JSON.stringify(oauthReqInfo)))
		const authUrl = authUrlObj.toString()

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
		const errorInfo = formatAuthError(AuthError.AUTH_URL_ERROR, { error })
		logger.error(errorInfo.message, { error })
		return new Response(errorInfo.message, { status: errorInfo.status })
	}
}
