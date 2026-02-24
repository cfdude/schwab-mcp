import { type OAuthHelpers } from '@cloudflare/workers-oauth-provider'
import {
	createApiClient,
	sanitizeKeyForLog,
	sanitizeError,
	SchwabAuthError,
	SchwabApiError,
	type TokenData,
} from '@sudowealth/schwab-api'
import { Hono } from 'hono'
import { type Env } from '../../types/env'
import { getConfig } from '../config'
import { LOGGER_CONTEXTS, APP_SERVER_NAME } from '../shared/constants'
import { makeKvTokenStore } from '../shared/kvTokenStore'
import { logger } from '../shared/log'
import { initializeSchwabAuthClient, redirectToSchwab } from './client'
import { parseRedirectApproval } from './cookies'
import { mapSchwabError } from './errorMapping'
import {
	AuthErrors,
	type AuthError,
	formatAuthError,
	createJsonErrorResponse,
} from './errors'
import { isClientApproved, approveClient } from './kvApprovalStore'
import { decodeAndVerifyState, extractClientIdFromState } from './stateUtils'
import { renderApprovalDialog } from './ui/approvalDialog'
import { APPROVAL_CONFIG } from './ui/config'

// Create Hono app with appropriate bindings
const app = new Hono<{ Bindings: Env & { OAUTH_PROVIDER: OAuthHelpers } }>()

// Create a scoped logger for OAuth handlers
const oauthLogger = logger.child(LOGGER_CONTEXTS.OAUTH_HANDLER)

// No need to store config locally, we'll build it per request

// Constants for distributed auth lock
const AUTH_LOCK_KEY = 'auth-lock'
const AUTH_LOCK_TTL = 60 // 60 seconds max lock duration
const AUTH_LOCK_WAIT_MS = 2000 // Wait 2 seconds between lock checks
const AUTH_LOCK_MAX_RETRIES = 5 // Max retries waiting for lock

/**
 * Distributed lock for OAuth flows to prevent multiple simultaneous browser auth attempts.
 * When multiple mcp-remote sessions detect they need auth, only one should open a browser.
 */
interface AuthLock {
	sessionId: string
	timestamp: number
	expiresAt: number
}

/**
 * Try to acquire the auth lock. Returns true if lock acquired, false if already held by another session.
 */
async function tryAcquireAuthLock(
	kv: any,
	sessionId: string,
): Promise<boolean> {
	try {
		const existing = await kv.get(AUTH_LOCK_KEY)
		if (existing) {
			const lock: AuthLock = JSON.parse(existing)
			// Check if lock is expired
			if (lock.expiresAt > Date.now()) {
				// Lock is still valid and held by another session
				oauthLogger.debug('Auth lock held by another session', {
					holder: lock.sessionId.substring(0, 8) + '...',
					expiresIn: Math.round((lock.expiresAt - Date.now()) / 1000) + 's',
				})
				return false
			}
			// Lock expired, we can take it
			oauthLogger.debug('Auth lock expired, acquiring')
		}

		// Acquire the lock
		const newLock: AuthLock = {
			sessionId,
			timestamp: Date.now(),
			expiresAt: Date.now() + AUTH_LOCK_TTL * 1000,
		}
		await kv.put(AUTH_LOCK_KEY, JSON.stringify(newLock), {
			expirationTtl: AUTH_LOCK_TTL,
		})
		oauthLogger.info('Auth lock acquired', {
			sessionId: sessionId.substring(0, 8) + '...',
		})
		return true
	} catch (error) {
		oauthLogger.error('Error acquiring auth lock', { error })
		// On error, proceed without lock (fail open)
		return true
	}
}

/**
 * Release the auth lock if held by this session
 */
async function releaseAuthLock(kv: any, sessionId: string): Promise<void> {
	try {
		const existing = await kv.get(AUTH_LOCK_KEY)
		if (existing) {
			const lock: AuthLock = JSON.parse(existing)
			if (lock.sessionId === sessionId) {
				await kv.delete(AUTH_LOCK_KEY)
				oauthLogger.debug('Auth lock released', {
					sessionId: sessionId.substring(0, 8) + '...',
				})
			}
		}
	} catch (error) {
		oauthLogger.error('Error releasing auth lock', { error })
	}
}

/**
 * Wait for auth lock to be released, checking periodically for valid tokens
 */
async function waitForAuthLockOrTokens(
	kv: any,
	schwabClientId: string,
): Promise<{ tokens: TokenData; schwabUserId: string } | null> {
	for (let i = 0; i < AUTH_LOCK_MAX_RETRIES; i++) {
		// Wait a bit
		await new Promise((resolve) => setTimeout(resolve, AUTH_LOCK_WAIT_MS))

		// Check if valid tokens are now available (another session might have completed auth)
		const tokens = await getValidSchwabTokens(kv, schwabClientId)
		if (tokens) {
			oauthLogger.info('Valid tokens found after waiting for lock', {
				schwabUserId: tokens.schwabUserId.substring(0, 8) + '...',
			})
			return tokens
		}

		// Check if lock is released
		const lockData = await kv.get(AUTH_LOCK_KEY)
		if (!lockData) {
			oauthLogger.debug('Auth lock released, but no tokens found yet')
			// Lock released but no tokens - we can try to acquire and auth
			return null
		}
	}

	oauthLogger.warn('Timed out waiting for auth lock')
	return null
}

/**
 * Create a smart redirect response that verifies mcp-remote's local callback server
 * is reachable before redirecting. If unreachable, retries with backoff and shows
 * clear fallback instructions since tokens are already saved server-side.
 */
function createSmartRedirectResponse(redirectTo: string): Response {
	const html = `<!DOCTYPE html>
<html>
<head>
	<title>Authorization Successful</title>
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
		.container { text-align: center; padding: 2rem; background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; margin: 1rem; }
		.spinner { width: 40px; height: 40px; border: 4px solid #e0e0e0; border-top: 4px solid #007bff; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 1rem; }
		@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
		h2 { color: #333; margin-bottom: 0.5rem; }
		p { color: #666; line-height: 1.5; }
		.status { font-size: 0.9rem; color: #888; margin-top: 1rem; }
		.success { color: #28a745; }
		.warning { color: #dc3545; }
		.fallback { display: none; text-align: left; margin-top: 1.5rem; padding: 1rem; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #ffc107; }
		.fallback h3 { color: #333; margin: 0 0 0.5rem 0; font-size: 1rem; }
		.fallback ol { margin: 0.5rem 0; padding-left: 1.5rem; }
		.fallback li { margin: 0.3rem 0; color: #555; font-size: 0.9rem; }
		.fallback .good-news { color: #28a745; font-weight: 600; margin-bottom: 0.5rem; }
		.retry-btn { display: none; margin-top: 1rem; padding: 0.5rem 1.5rem; background: #007bff; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 0.9rem; }
		.retry-btn:hover { background: #0056b3; }
	</style>
</head>
<body>
	<div class="container">
		<div class="spinner" id="spinner"></div>
		<h2 id="title">Authorization Successful</h2>
		<p id="message">Verifying local connection...</p>
		<p class="status" id="status">Attempt 1 of 5</p>
		<div class="fallback" id="fallback">
			<p class="good-news">Your Schwab tokens are saved on the server.</p>
			<h3>The local callback server isn't responding. To connect:</h3>
			<ol>
				<li>Make sure Claude Desktop or Claude Code is running</li>
				<li>Restart the application to trigger a fresh MCP connection</li>
				<li>The server will find your saved tokens automatically</li>
			</ol>
		</div>
		<button class="retry-btn" id="retryBtn" onclick="startRetry()">Try Again</button>
	</div>
	<script>
		const redirectUrl = ${JSON.stringify(redirectTo)};
		let attempt = 0;
		const maxAttempts = 5;
		const delays = [1000, 2000, 3000, 4000, 5000]; // backoff

		function updateStatus(msg, className) {
			const el = document.getElementById('status');
			el.textContent = msg;
			el.className = 'status ' + (className || '');
		}

		async function tryRedirect() {
			attempt++;
			updateStatus('Attempt ' + attempt + ' of ' + maxAttempts);
			document.getElementById('message').textContent = 'Checking if Claude is ready to receive the callback...';

			try {
				// Extract just the origin + path from the redirect URL to probe
				const url = new URL(redirectUrl);
				const probeUrl = url.origin;

				// Try to reach the local callback server
				// We use a short timeout and mode: no-cors since the server may not have CORS headers
				const controller = new AbortController();
				const timeout = setTimeout(() => controller.abort(), 3000);

				await fetch(probeUrl, {
					method: 'HEAD',
					mode: 'no-cors',
					signal: controller.signal
				});
				clearTimeout(timeout);

				// If we get here (even opaque response), the server is listening
				updateStatus('Connected! Redirecting...', 'success');
				document.getElementById('message').textContent = 'Local server is ready. Completing authentication...';

				// Small delay then redirect
				setTimeout(function() {
					window.location.href = redirectUrl;
				}, 500);

			} catch (err) {
				if (attempt < maxAttempts) {
					updateStatus('Local server not ready, retrying in ' + (delays[attempt - 1] / 1000) + 's... (attempt ' + attempt + '/' + maxAttempts + ')');
					setTimeout(tryRedirect, delays[attempt - 1]);
				} else {
					// All attempts failed - show fallback
					document.getElementById('spinner').style.display = 'none';
					document.getElementById('title').textContent = 'Almost Done';
					document.getElementById('message').textContent = '';
					updateStatus('Could not reach local callback server after ' + maxAttempts + ' attempts', 'warning');
					document.getElementById('fallback').style.display = 'block';
					document.getElementById('retryBtn').style.display = 'inline-block';
				}
			}
		}

		function startRetry() {
			attempt = 0;
			document.getElementById('spinner').style.display = 'block';
			document.getElementById('title').textContent = 'Authorization Successful';
			document.getElementById('fallback').style.display = 'none';
			document.getElementById('retryBtn').style.display = 'none';
			tryRedirect();
		}

		// Start immediately
		tryRedirect();
	</script>
</body>
</html>`;

	return new Response(html, {
		status: 200,
		headers: {
			'Content-Type': 'text/html; charset=utf-8',
		},
	})
}

/**
 * Check if existing Schwab tokens in KV are valid (not expired)
 * Returns the tokens and schwabUserId if valid, null otherwise
 */
async function getValidSchwabTokens(
	kv: any, // KVNamespace - using any to avoid type conflicts between workers-types versions
	schwabClientId: string,
): Promise<{ tokens: TokenData; schwabUserId: string } | null> {
	const kvToken = makeKvTokenStore(kv)

	// Try to load tokens from the stable SCHWAB_CLIENT_ID key
	const tokens = await kvToken.load({ clientId: schwabClientId })

	if (!tokens) {
		oauthLogger.debug('No existing Schwab tokens found in KV')
		return null
	}

	// Check if access token is expired (with 5 minute buffer for safety)
	const now = Date.now()
	const bufferMs = 5 * 60 * 1000 // 5 minutes
	const isExpired = tokens.expiresAt < now + bufferMs

	if (isExpired) {
		oauthLogger.debug('Existing Schwab tokens are expired or expiring soon', {
			expiresAt: new Date(tokens.expiresAt).toISOString(),
			now: new Date(now).toISOString(),
		})

		// Check if we have a valid refresh token (Schwab refresh tokens last 7 days)
		if (tokens.refreshToken) {
			oauthLogger.debug(
				'Have refresh token, will attempt refresh during first API call',
			)
			// Return the tokens anyway - the EnhancedTokenManager will handle refresh
			// We need to find the schwabUserId by checking other keys
			const schwabUserId = await findSchwabUserIdFromKV(kv, schwabClientId)
			if (schwabUserId) {
				return { tokens, schwabUserId }
			}
		}

		return null
	}

	// Tokens are valid, find the schwabUserId
	const schwabUserId = await findSchwabUserIdFromKV(kv, schwabClientId)
	if (!schwabUserId) {
		oauthLogger.warn(
			'Valid tokens found but no schwabUserId - token may need re-auth',
		)
		return null
	}

	oauthLogger.debug('Found valid Schwab tokens in KV', {
		expiresAt: new Date(tokens.expiresAt).toISOString(),
		schwabUserId: schwabUserId.substring(0, 8) + '...',
	})

	return { tokens, schwabUserId }
}

/**
 * Find the schwabUserId from KV by checking known token keys
 * This is a workaround for the chicken-and-egg problem
 */
async function findSchwabUserIdFromKV(
	kv: any, // KVNamespace - using any to avoid type conflicts between workers-types versions
	schwabClientId: string,
): Promise<string | null> {
	try {
		// List all keys that start with 'token:'
		const list = await kv.list({ prefix: 'token:' })

		for (const key of list.keys) {
			// Skip the stable SCHWAB_CLIENT_ID key - we're looking for schwabUserId keys
			if (key.name === `token:${schwabClientId}`) {
				continue
			}

			// schwabUserId format is typically a UUID like 'd5be5ccf-8533-b8d6-40e7-20c6fcbb1b15'
			const potentialUserId = key.name.replace('token:', '')

			// Check if it looks like a UUID (schwabUserId format)
			const uuidRegex =
				/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
			if (uuidRegex.test(potentialUserId)) {
				// Verify this key has the same tokens as the stable key
				const tokenData = await kv.get(key.name)
				const stableTokenData = await kv.get(`token:${schwabClientId}`)

				if (tokenData && stableTokenData) {
					const parsed = JSON.parse(tokenData)
					const stableParsed = JSON.parse(stableTokenData)

					// If refresh tokens match, this is the right user
					if (parsed.refreshToken === stableParsed.refreshToken) {
						return potentialUserId
					}
				}
			}
		}

		oauthLogger.debug('Could not find schwabUserId in KV')
		return null
	} catch (error) {
		oauthLogger.error('Error finding schwabUserId from KV', {
			error: sanitizeError(error),
		})
		return null
	}
}

/**
 * GET /authorize - Entry point for OAuth authorization flow
 *
 * This endpoint has three paths:
 * 1. If valid Schwab tokens exist in KV, complete OAuth immediately (no user interaction)
 * 2. If client is approved but tokens are missing/expired, redirect to Schwab
 * 3. If client not approved, show approval dialog
 *
 * This prevents multiple simultaneous OAuth flows when multiple projects connect
 */
app.get('/authorize', async (c) => {
	try {
		const config = getConfig(c.env)
		const oauthReqInfo = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw)
		const { clientId } = oauthReqInfo

		if (!clientId) {
			const error = new AuthErrors.MissingClientId()
			const errorInfo = formatAuthError(error)
			oauthLogger.error(errorInfo.message)
			const jsonResponse = createJsonErrorResponse(error)
			return c.json(jsonResponse, errorInfo.status as any)
		}

		// OPTIMIZATION: Check if we already have valid Schwab tokens in KV
		// If so, we can complete the OAuth flow immediately without user interaction
		// This prevents multiple browser windows opening when multiple projects connect
		const existingTokens = await getValidSchwabTokens(
			config.OAUTH_KV,
			config.SCHWAB_CLIENT_ID,
		)

		if (existingTokens) {
			oauthLogger.info(
				'Found valid Schwab tokens in KV - completing OAuth without user interaction',
				{
					schwabUserId: existingTokens.schwabUserId.substring(0, 8) + '...',
				},
			)

			// Complete the authorization flow immediately
			const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
				request: oauthReqInfo,
				userId: existingTokens.schwabUserId,
				metadata: { label: existingTokens.schwabUserId },
				scope: oauthReqInfo.scope,
				props: {
					schwabUserId: existingTokens.schwabUserId,
					clientId: clientId,
				},
			})

			oauthLogger.info(
				'OAuth flow completed immediately using existing tokens',
				{
					redirectTo: redirectTo.substring(0, 50) + '...',
				},
			)

			// Use smart redirect that verifies mcp-remote is listening before redirecting
			return createSmartRedirectResponse(redirectTo)
		}

		// No valid tokens in KV - need to redirect to Schwab OAuth
		// Use distributed lock to prevent multiple browser windows opening
		const sessionId = clientId // Use mcp-remote's clientId as session identifier

		// Try to acquire the auth lock
		const lockAcquired = await tryAcquireAuthLock(config.OAUTH_KV, sessionId)

		if (!lockAcquired) {
			// Another session is currently doing auth - wait for it
			oauthLogger.info(
				'Another session is authenticating, waiting for result...',
				{
					sessionId: sessionId.substring(0, 8) + '...',
				},
			)

			const tokensAfterWait = await waitForAuthLockOrTokens(
				config.OAUTH_KV,
				config.SCHWAB_CLIENT_ID,
			)

			if (tokensAfterWait) {
				// Another session completed auth - use their tokens
				oauthLogger.info("Using tokens from another session's auth", {
					schwabUserId: tokensAfterWait.schwabUserId.substring(0, 8) + '...',
				})

				const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization(
					{
						request: oauthReqInfo,
						userId: tokensAfterWait.schwabUserId,
						metadata: { label: tokensAfterWait.schwabUserId },
						scope: oauthReqInfo.scope,
						props: {
							schwabUserId: tokensAfterWait.schwabUserId,
							clientId: clientId,
						},
					},
				)

				// Use smart redirect that verifies mcp-remote is listening before redirecting
				return createSmartRedirectResponse(redirectTo)
			}

			// Timed out waiting - try to acquire lock and proceed
			oauthLogger.warn(
				'Timed out waiting for other session, proceeding with auth',
			)
		}

		// Check if the Schwab app has been approved before (using stable SCHWAB_CLIENT_ID, not random mcp-remote clientId)
		// This ensures users only need to approve once, regardless of which mcp-remote session they use
		if (await isClientApproved(config.OAUTH_KV, config.SCHWAB_CLIENT_ID)) {
			oauthLogger.debug(
				'Schwab app already approved, redirecting to Schwab OAuth',
				{
					schwabClientId: config.SCHWAB_CLIENT_ID.substring(0, 8) + '...',
				},
			)
			return redirectToSchwab(c, config, oauthReqInfo)
		}

		// Show approval dialog (Cloudflare style)
		const clientInfo = await c.env.OAUTH_PROVIDER.lookupClient(clientId)
		const serverInfo = {
			name: APP_SERVER_NAME,
			logo: APPROVAL_CONFIG.SHOW_LOGO ? APPROVAL_CONFIG.LOGO_URL : undefined,
		}

		return renderApprovalDialog(c.req.raw, {
			client: clientInfo,
			server: serverInfo,
			state: { oauthReqInfo },
			config,
		})
	} catch (error) {
		const authError = new AuthErrors.AuthRequest()
		const errorInfo = formatAuthError(authError, { error })
		oauthLogger.error(errorInfo.message, { error: sanitizeError(error) })
		const jsonResponse = createJsonErrorResponse(authError)
		return c.json(jsonResponse, errorInfo.status as any)
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
		const config = getConfig(c.env)
		const { state, headers } = await parseRedirectApproval(c.req.raw, config)

		if (!state.oauthReqInfo) {
			const error = new AuthErrors.MissingState()
			const errorInfo = formatAuthError(error)
			oauthLogger.error(errorInfo.message)
			const jsonResponse = createJsonErrorResponse(error)
			return c.json(jsonResponse, errorInfo.status as any)
		}

		// Pass the actual AuthRequest object to redirectToSchwab
		const authRequestForSchwab = state.oauthReqInfo

		// Validate required AuthRequest fields before passing to redirectToSchwab
		if (!authRequestForSchwab?.clientId || !authRequestForSchwab?.scope) {
			const error = new AuthErrors.InvalidState()
			const errorInfo = formatAuthError(error, {
				missingFields: {
					clientId: !authRequestForSchwab?.clientId,
					scope: !authRequestForSchwab?.scope,
				},
			})
			oauthLogger.error(errorInfo.message)
			const jsonResponse = createJsonErrorResponse(
				error,
				undefined,
				errorInfo.details as Record<string, any>,
			)
			return c.json(jsonResponse, errorInfo.status as any)
		}

		// Store the Schwab app approval in KV for future sessions (using stable SCHWAB_CLIENT_ID)
		// This way, users only need to approve once regardless of mcp-remote session
		await approveClient(config.OAUTH_KV, config.SCHWAB_CLIENT_ID)
		oauthLogger.info('Schwab app approved for future sessions', {
			schwabClientId: config.SCHWAB_CLIENT_ID.substring(0, 8) + '...',
		})

		return redirectToSchwab(c, config, authRequestForSchwab, headers)
	} catch (error) {
		const authError = new AuthErrors.AuthApproval()
		const errorInfo = formatAuthError(authError, { error })
		oauthLogger.error(errorInfo.message, { error: sanitizeError(error) })
		const jsonResponse = createJsonErrorResponse(authError)
		return c.json(jsonResponse, errorInfo.status as any)
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
		const config = getConfig(c.env)

		// Extract state and code from query parameters
		const stateParam = c.req.query('state')
		const code = c.req.query('code')

		if (!stateParam || !code) {
			const error = new AuthErrors.MissingParameters()
			const errorInfo = formatAuthError(error, {
				hasState: !!stateParam,
				hasCode: !!code,
			})
			oauthLogger.error(errorInfo.message)
			const jsonResponse = createJsonErrorResponse(
				error,
				undefined,
				errorInfo.details as Record<string, any>,
			)
			return c.json(jsonResponse, errorInfo.status as any)
		}

		// Parse the state using our utility function.
		// `decodedStateAsAuthRequest` is the AuthRequest object itself that was sent to Schwab.
		const decodedStateAsAuthRequest = await decodeAndVerifyState(
			config,
			stateParam,
		)

		if (!decodedStateAsAuthRequest) {
			const error = new AuthErrors.InvalidState()
			const errorInfo = formatAuthError(error)
			oauthLogger.error(errorInfo.message)
			const jsonResponse = createJsonErrorResponse(error)
			return c.json(jsonResponse, errorInfo.status as any)
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
			const error = new AuthErrors.InvalidState()
			const errorInfo = formatAuthError(error, {
				detail:
					'Decoded state object from Schwab callback is missing required AuthRequest fields (clientId, redirectUri, or scope).',
			})
			oauthLogger.error(errorInfo.message)
			const jsonResponse = createJsonErrorResponse(
				error,
				undefined,
				errorInfo.details as Record<string, any>,
			)
			return c.json(jsonResponse, errorInfo.status as any)
		}

		// Set up redirect URI and token storage using centralized KV helper
		const redirectUri = config.SCHWAB_REDIRECT_URI
		const kvToken = makeKvTokenStore(config.OAUTH_KV)

		// Initial token identifiers (before we get schwabUserId)
		const getInitialTokenIds = () => ({ clientId: clientIdFromState })

		const saveToken = async (tokenData: TokenData) => {
			const ids = getInitialTokenIds()
			await kvToken.save(ids, tokenData)
			oauthLogger.debug('Token saved to KV', { key: kvToken.kvKey(ids) })
		}

		const loadToken = async (): Promise<TokenData | null> => {
			return await kvToken.load(getInitialTokenIds())
		}

		// Use the validated config for auth client to ensure consistency
		const auth = initializeSchwabAuthClient(
			config,
			redirectUri,
			loadToken,
			saveToken,
		)

		// Exchange the code for tokens with enhanced error handling
		oauthLogger.info(
			'Exchanging authorization code for tokens with state parameter for PKCE',
		)
		try {
			// Pass the stateParam directly to EnhancedTokenManager.exchangeCode
			// EnhancedTokenManager will handle extracting the code_verifier from it
			await auth.exchangeCode(code, stateParam)
		} catch (exchangeError) {
			oauthLogger.error('Token exchange failed', {
				error: sanitizeError(exchangeError),
				message:
					exchangeError instanceof Error
						? exchangeError.message
						: String(exchangeError),
			})
			throw new AuthErrors.TokenExchange()
		}

		// Log token exchange success (without sensitive details)
		oauthLogger.info('Token exchange successful')

		// Create API client (temporary for auth flow)
		oauthLogger.info('Creating Schwab API client')
		let client
		try {
			client = createApiClient({
				config: { environment: 'PRODUCTION' },
				auth,
			})
		} catch (clientError) {
			oauthLogger.error('Failed to create API client', {
				error: sanitizeError(clientError),
				message:
					clientError instanceof Error
						? clientError.message
						: String(clientError),
			})
			throw new AuthErrors.AuthCallback()
		}

		// Fetch user info to get the Schwab user ID
		oauthLogger.info('Fetching user preferences to get Schwab user ID')
		let userPreferences
		try {
			userPreferences = await client.trader.userPreference.getUserPreference()
		} catch (preferencesError) {
			oauthLogger.error('Failed to fetch user preferences', {
				error: sanitizeError(preferencesError),
				message:
					preferencesError instanceof Error
						? preferencesError.message
						: String(preferencesError),
			})
			throw new AuthErrors.NoUserId()
		}

		const userIdFromSchwab =
			userPreferences?.streamerInfo?.[0]?.schwabClientCorrelId

		if (!userIdFromSchwab) {
			const error = new AuthErrors.NoUserId()
			const errorInfo = formatAuthError(error)
			oauthLogger.error(errorInfo.message)
			const jsonResponse = createJsonErrorResponse(error)
			return c.json(jsonResponse, errorInfo.status as any)
		}

		// Save token under multiple keys for reliable lookup:
		// 1. schwabUserId key - for user-specific access
		// 2. SCHWAB_CLIENT_ID key - for initial connection before schwabUserId is known
		try {
			const currentTokenData = await kvToken.load({
				clientId: clientIdFromState,
			})
			if (currentTokenData) {
				// Save under schwabUserId key (user-specific)
				await kvToken.save({ schwabUserId: userIdFromSchwab }, currentTokenData)

				// ALSO save under stable SCHWAB_CLIENT_ID key (for reconnection lookup)
				// This solves the chicken-and-egg problem: we need schwabUserId to find tokens,
				// but we only get schwabUserId after auth. This key is always available.
				await kvToken.save(
					{ clientId: config.SCHWAB_CLIENT_ID },
					currentTokenData,
				)

				oauthLogger.info('Token saved to multiple keys for reliable lookup', {
					schwabUserIdKey: sanitizeKeyForLog(
						kvToken.kvKey({ schwabUserId: userIdFromSchwab }),
					),
					stableClientIdKey: sanitizeKeyForLog(
						kvToken.kvKey({ clientId: config.SCHWAB_CLIENT_ID }),
					),
				})
			}
		} catch (migrationError) {
			oauthLogger.warn(
				'Token migration failed, continuing with authorization',
				{
					error:
						migrationError instanceof Error
							? migrationError.message
							: String(migrationError),
				},
			)
		}

		// Complete the authorization flow using the decoded AuthRequest object
		const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
			request: decodedStateAsAuthRequest,
			userId: userIdFromSchwab,
			metadata: { label: userIdFromSchwab },
			scope: decodedStateAsAuthRequest.scope,
			props: {
				// Only store IDs for token key derivation - tokens are in KV
				schwabUserId: userIdFromSchwab,
				clientId: clientIdFromState,
			},
		})

		// Release the auth lock now that tokens are saved
		// This allows other waiting sessions to use the new tokens
		await releaseAuthLock(config.OAUTH_KV, clientIdFromState)
		oauthLogger.info('Auth callback completed, lock released')

		// Use smart redirect that verifies mcp-remote is listening before redirecting
		// At this point Schwab tokens are already saved in KV, so even if the redirect
		// fails, the user can reconnect by restarting Claude and tokens will be found
		return createSmartRedirectResponse(redirectTo)
	} catch (error) {
		const isSchwabAuthError = error instanceof SchwabAuthError
		const isSchwabApiErrorInstance = error instanceof SchwabApiError

		let mcpError: AuthError = new AuthErrors.AuthCallback() // Default MCP error for this handler
		let detailMessage = error instanceof Error ? error.message : String(error)
		let httpStatus = 500 // Default HTTP status
		let requestId: string | undefined

		if (isSchwabAuthError) {
			const schwabAuthErr = error as SchwabAuthError
			const errorMapping = mapSchwabError(
				schwabAuthErr.code,
				schwabAuthErr.message,
				schwabAuthErr.status,
			)
			mcpError = errorMapping.mcpError
			detailMessage = errorMapping.detailMessage
			httpStatus = errorMapping.httpStatus

			// Extract requestId if available
			if (typeof (schwabAuthErr as any).getRequestId === 'function') {
				requestId = (schwabAuthErr as any).getRequestId()
			}
		} else if (isSchwabApiErrorInstance) {
			const schwabApiErr = error as SchwabApiError
			mcpError = new AuthErrors.ApiResponse()
			detailMessage = `API request failed during authorization: ${schwabApiErr.message}`
			httpStatus = schwabApiErr.status || 500

			// Extract requestId if available
			if (typeof (schwabApiErr as any).getRequestId === 'function') {
				requestId = (schwabApiErr as any).getRequestId()
			}
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
			requestId,
		})

		oauthLogger.error(`Auth callback failed: ${errorInfo.message}`, {
			errorType: mcpError.constructor.name,
			...(requestId && { requestId }),
		})

		const jsonResponse = createJsonErrorResponse(mcpError, requestId, {})

		return c.json(jsonResponse, errorInfo.status as any)
	}
})

/**
 * Re-authentication Endpoint
 *
 * GET /reauth - Clears server-side tokens and provides instructions for re-authentication
 *
 * This endpoint is designed to be called when a 401 error occurs. It:
 * 1. Clears all Schwab tokens from KV storage
 * 2. Provides a simple HTML page with re-auth instructions
 * 3. Optionally auto-redirects to start the OAuth flow
 *
 * Query params:
 * - auto=true: Automatically trigger OAuth flow after clearing (for browser use)
 */
app.get('/reauth', async (c) => {
	try {
		const config = getConfig(c.env)
		const kvToken = makeKvTokenStore(config.OAUTH_KV)

		// Clear all known token keys
		let tokensCleared = false
		try {
			// Clear the stable SCHWAB_CLIENT_ID key
			await kvToken.clear({ clientId: config.SCHWAB_CLIENT_ID })
			tokensCleared = true
			oauthLogger.info('Server-side Schwab tokens cleared via /reauth endpoint')
		} catch (clearError) {
			oauthLogger.error('Failed to clear tokens', {
				error: sanitizeError(clearError),
			})
		}

		const html = `<!DOCTYPE html>
<html>
<head>
	<title>Schwab MCP - Re-authentication Required</title>
	<style>
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
			display: flex;
			justify-content: center;
			align-items: center;
			min-height: 100vh;
			margin: 0;
			background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
			color: #fff;
		}
		.container {
			text-align: center;
			padding: 3rem;
			background: rgba(255, 255, 255, 0.05);
			border-radius: 16px;
			box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
			backdrop-filter: blur(10px);
			max-width: 600px;
		}
		.icon {
			font-size: 4rem;
			margin-bottom: 1rem;
		}
		h1 {
			margin: 0 0 1rem 0;
			font-size: 1.5rem;
		}
		.status {
			background: ${tokensCleared ? '#10b981' : '#ef4444'};
			color: white;
			padding: 0.5rem 1rem;
			border-radius: 8px;
			margin: 1rem 0;
			display: inline-block;
		}
		.instructions {
			text-align: left;
			background: rgba(255, 255, 255, 0.1);
			padding: 1.5rem;
			border-radius: 8px;
			margin: 1.5rem 0;
		}
		.instructions h3 {
			margin-top: 0;
			color: #60a5fa;
		}
		.instructions ol {
			margin: 0;
			padding-left: 1.5rem;
		}
		.instructions li {
			margin: 0.75rem 0;
			line-height: 1.5;
		}
		.instructions code {
			background: rgba(0, 0, 0, 0.3);
			padding: 0.25rem 0.5rem;
			border-radius: 4px;
			font-size: 0.9rem;
			word-break: break-all;
		}
		.warning {
			background: rgba(251, 191, 36, 0.2);
			border: 1px solid #fbbf24;
			border-radius: 8px;
			padding: 1rem;
			margin: 1rem 0;
			text-align: left;
		}
		.warning h4 {
			margin: 0 0 0.5rem 0;
			color: #fbbf24;
		}
		.warning p {
			margin: 0;
			font-size: 0.9rem;
		}
		.note {
			font-size: 0.9rem;
			color: #94a3b8;
			margin-top: 1.5rem;
		}
	</style>
</head>
<body>
	<div class="container">
		<div class="icon">🔐</div>
		<h1>Schwab MCP Re-authentication</h1>
		<div class="status">
			${tokensCleared ? '✓ Server tokens cleared successfully' : '⚠ Could not clear tokens'}
		</div>

		<div class="warning">
			<h4>⚠️ Important: Order Matters!</h4>
			<p>You must restart Claude Desktop <strong>before</strong> the OAuth callback will work.
			The callback redirects to a local server that only runs when Claude Desktop is open.</p>
		</div>

		<div class="instructions">
			<h3>Next Steps (follow in order)</h3>
			<ol>
				<li><strong>Close this browser tab</strong> (don't complete OAuth yet)</li>
				<li>Clear your local MCP auth cache in Terminal:
					<br><code>rm -rf ~/.mcp-auth/mcp-remote-*/</code>
				</li>
				<li><strong>Restart Claude Desktop</strong> (Cmd+Q, then reopen)</li>
				<li>Try to use a Schwab tool in Claude - this will trigger OAuth</li>
				<li>Complete the Schwab login in the browser that opens</li>
			</ol>
		</div>

		<p class="note">
			<strong>Why this order?</strong> The OAuth callback redirects to localhost where mcp-remote
			(Claude's MCP handler) listens. If Claude Desktop isn't running, the callback fails with
			"cannot connect to localhost". Restarting Claude first ensures mcp-remote is ready.
		</p>
	</div>
</body>
</html>`

		return new Response(html, {
			status: 200,
			headers: { 'Content-Type': 'text/html; charset=utf-8' },
		})
	} catch (error) {
		oauthLogger.error('Re-auth endpoint failed', { error: sanitizeError(error) })
		return c.json({ error: 'Re-authentication failed', message: String(error) }, 500)
	}
})

export { app as SchwabHandler }
