import { type AuthRequest } from '@cloudflare/workers-oauth-provider'
import { logger } from '../shared/logger'
import { AuthError, formatAuthError } from './errorMessages'

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
 * Decodes and verifies a state parameter, returning structured data.
 * Safely handles base64 decoding before attempting to parse JSON.
 *
 * NOTE: This extracts the application-specific portion of the state after
 * EnhancedTokenManager has processed its PKCE-related data. The full original
 * stateParam should still be passed to ETM.exchangeCode() before using this function.
 *
 * @param stateParam - The state parameter to decode and verify.
 * @returns The parsed state data with typed access to common fields, or null if decoding fails.
 */
export function decodeAndVerifyState(stateParam: string): AuthRequest | null {
	try {
		// First URL-decode the state
		const urlDecodedState = decodeURIComponent(stateParam)

		// Convert from base64url to base64
		let base64State = urlDecodedState.replace(/-/g, '+').replace(/_/g, '/')

		// Add padding if needed
		while (base64State.length % 4 !== 0) {
			base64State += '='
		}

		// Now attempt to decode
		try {
			const decodedState = atob(base64State)
			// Parse JSON
			return JSON.parse(decodedState) as AuthRequest
		} catch (error) {
			logger.error('[ERROR] Error in base64 decoding or JSON parsing:', error)
			return null
		}
	} catch (error) {
		logger.error('[ERROR] Error decoding state in decodeAndVerifyState:', error)
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
		const errorInfo = formatAuthError(AuthError.CLIENT_ID_EXTRACTION_ERROR)
		throw new Error(errorInfo.message)
	}

	return clientId
}
