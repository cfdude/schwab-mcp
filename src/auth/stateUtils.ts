import { type AuthRequest } from '@cloudflare/workers-oauth-provider'
import { safeBase64Decode } from '@sudowealth/schwab-api'
import { type ValidatedEnv } from '../../types/env'
import { LOGGER_CONTEXTS } from '../shared/constants'
import { logger } from '../shared/logger'
import { AuthErrors } from './errors'
import * as jwt from './jwt'

// Create scoped logger for OAuth state operations
const stateLogger = logger.child(LOGGER_CONTEXTS.STATE_UTILS)

/**
 * IMPORTANT: EnhancedTokenManager State Handling
 *
 * EnhancedTokenManager in @sudowealth/schwab-api handles PKCE flow internally:
 * 1. When getAuthorizationUrl is called, it generates code_verifier and code_challenge
 * 2. It embeds the code_verifier into the state parameter along with application state
 * 3. In the OAuth callback, the full stateParam must be passed to exchangeCode method
 * 4. EnhancedTokenManager extracts the code_verifier from the state for the token exchange
 *
 * State flow:
 * - client.ts: redirectToSchwab() passes application state to ETM.getAuthorizationUrl()
 * - ETM combines application state with its own PKCE data
 * - handler.ts: /callback receives the state and passes it to ETM.exchangeCode()
 * - Our decodeAndVerifyState still works to extract application data after ETM processing
 */


/**
 * Interface for structured state data
 */
export interface StateData {
	clientId?: string
	userId?: string
	oauthReqInfo?: AuthRequest
	[key: string]: any
}


/**
 * Encodes state with integrity protection using JWT
 * @param state - The state object to encode
 * @returns JWT token with HMAC signature and expiry
 */
export async function encodeStateWithIntegrity(
	config: ValidatedEnv,
	state: AuthRequest,
): Promise<string> {
	return await jwt.sign(config.COOKIE_ENCRYPTION_KEY, state)
}

/**
 * Decodes and verifies a state parameter with integrity checking.
 * Uses JWT format with HMAC signature verification and expiry checking.
 *
 * NOTE: This extracts the application-specific portion of the state after
 * EnhancedTokenManager has processed its PKCE-related data. The full original
 * stateParam should still be passed to ETM.exchangeCode() before using this function.
 *
 * @param stateParam - The state parameter to decode and verify.
 * @returns The parsed state data with typed access to common fields, or null if decoding/verification fails.
 */
export async function decodeAndVerifyState(
	config: ValidatedEnv,
	stateParam: string,
): Promise<AuthRequest | null> {
	try {
		// The state parameter may be URL-encoded when received from query params
		const decodedParam = stateParam.includes('%')
			? decodeURIComponent(stateParam)
			: stateParam

		// Try to decode as JWT format first
		try {
			return await jwt.verify<AuthRequest>(
				config.COOKIE_ENCRYPTION_KEY,
				decodedParam,
			)
		} catch (jwtError) {
			// If JWT verification fails, try legacy format
			stateLogger.info(
				'State not in JWT format, trying legacy decoding:',
				jwtError instanceof Error ? jwtError.message : 'Unknown error',
			)
		}

		// Legacy format: direct base64 encoded JSON
		try {
			const decodedState = safeBase64Decode(decodedParam)
			return JSON.parse(decodedState) as AuthRequest
		} catch (error) {
			stateLogger.error(
				'[ERROR] Error in base64 decoding or JSON parsing:',
				error,
			)
			return null
		}
	} catch (error) {
		stateLogger.error(
			'[ERROR] Error decoding state in decodeAndVerifyState:',
			error,
		)
		return null
	}
}

/**
 * Extracts the client ID from a state object, handling different state structures.
 *
 * @param state - The decoded state object.
 * @returns The client ID from the state.
 * @throws Error if client ID cannot be extracted.
 */
export function extractClientIdFromState(state: StateData): string {
	const clientId = state.clientId || state.oauthReqInfo?.clientId

	if (!clientId) {
		throw new AuthErrors.ClientIdExtraction()
	}

	return clientId
}
