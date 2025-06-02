import { type AuthRequest } from '@cloudflare/workers-oauth-provider'
import { safeBase64Decode } from '@sudowealth/schwab-api'
import { type ValidatedEnv } from '../../types/env'
import { LOGGER_CONTEXTS } from '../shared/constants'
import { logger } from '../shared/log'
import { AuthErrors } from './errors'
import { StateSchema, type StateData as StateDataFromSchema } from './schemas'
import { signState, verifyState } from './utils/jwt'

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
 * Re-export StateData type from schemas
 */
export type StateData = StateDataFromSchema

/**
 * Encodes state with integrity protection using JWT
 * @param state - The state object to encode
 * @returns JWT token with HMAC signature and expiry
 */
export async function encodeStateWithIntegrity<T = AuthRequest>(
	config: ValidatedEnv,
	state: T,
): Promise<string> {
	return await signState(
		config.COOKIE_ENCRYPTION_KEY,
		state as Record<string, unknown>,
		config.JWT_STATE_EXPIRATION_SECONDS ?? 180, // Default to 3 minutes
	)
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
export async function decodeAndVerifyState<T = AuthRequest>(
	config: ValidatedEnv,
	stateParam: string,
): Promise<T | null> {
	try {
		// The state parameter may be URL-encoded when received from query params
		const decodedParam = stateParam.includes('%')
			? decodeURIComponent(stateParam)
			: stateParam

		// Try to decode as JWT format first
		try {
			const payload = await verifyState<Record<string, unknown>>(
				config.COOKIE_ENCRYPTION_KEY,
				decodedParam,
			)
			// Validate with Zod schema
			return StateSchema.parse(payload) as T
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
			const parsed = JSON.parse(decodedState)
			// Validate with Zod schema
			return StateSchema.parse(parsed) as T
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
export function extractClientIdFromState(
	state: StateData | AuthRequest,
): string {
	// Handle AuthRequest objects directly
	if ('clientId' in state && typeof state.clientId === 'string') {
		return state.clientId
	}

	// Handle StateData objects
	const stateData = state as StateData
	const clientId = stateData.clientId || stateData.oauthReqInfo?.clientId

	if (!clientId) {
		throw new AuthErrors.ClientIdExtraction()
	}

	return clientId
}
