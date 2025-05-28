import { type AuthRequest } from '@cloudflare/workers-oauth-provider'
import { safeBase64Decode } from '@sudowealth/schwab-api'
import { type ValidatedEnv } from '../../types/env'
import { logger } from '../shared/logger'
import { createAuthError } from './errors'

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
 * Creates an HMAC signature for state integrity verification
 * @param data - The data to sign
 * @param secret - The secret key for HMAC
 * @returns Base64 encoded HMAC signature
 */
async function createHmacSignature(
	data: string,
	secret: string,
): Promise<string> {
	const encoder = new TextEncoder()
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign'],
	)

	const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data))
	return btoa(String.fromCharCode(...new Uint8Array(signature)))
}

/**
 * Verifies the HMAC signature of the state data using timing-safe comparison
 * @param data - The data to verify
 * @param signature - The signature to verify against
 * @param secret - The secret key for HMAC
 * @returns True if signature is valid
 */
async function verifyHmacSignature(
	data: string,
	signature: string,
	secret: string,
): Promise<boolean> {
	const encoder = new TextEncoder()
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['verify'],
	)

	// Decode the base64 signature to get the raw bytes
	try {
		const signatureBytes = Uint8Array.from(atob(signature), (c) =>
			c.charCodeAt(0),
		)

		// Use crypto.subtle.verify for timing-safe comparison
		return await crypto.subtle.verify(
			'HMAC',
			key,
			signatureBytes,
			encoder.encode(data),
		)
	} catch (e) {
		// If decoding fails, signature is invalid
		logger.error('[ERROR] Error in verifyHmacSignature:', e)
		return false
	}
}

/**
 * Encodes state with integrity protection using HMAC
 * @param state - The state object to encode
 * @returns Base64 encoded state with HMAC signature
 */
export async function encodeStateWithIntegrity(
	config: ValidatedEnv,
	state: AuthRequest,
): Promise<string> {
	const stateJson = JSON.stringify(state)
	const stateBase64 = btoa(stateJson)
	const signature = await createHmacSignature(
		stateBase64,
		config.COOKIE_ENCRYPTION_KEY,
	)

	// Combine state and signature
	const signedState = JSON.stringify({
		data: stateBase64,
		signature: signature,
	})

	return btoa(signedState)
}

/**
 * Decodes and verifies a state parameter with integrity checking.
 * Handles the double-encoding issue and verifies HMAC signature.
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

		// Try to decode as our signed state format first
		try {
			const signedStateJson = safeBase64Decode(decodedParam)
			const signedState = JSON.parse(signedStateJson) as {
				data?: string
				signature?: string
			}

			if (signedState.data && signedState.signature) {
				// Verify HMAC signature
				const isValid = await verifyHmacSignature(
					signedState.data,
					signedState.signature,
					config.COOKIE_ENCRYPTION_KEY,
				)

				if (!isValid) {
					logger.error('[ERROR] State HMAC signature verification failed')
					return null
				}

				// Decode the verified state data
				const stateJson = safeBase64Decode(signedState.data)
				return JSON.parse(stateJson) as AuthRequest
			}
		} catch {
			// Fall back to legacy format without HMAC for backward compatibility
			logger.info('State not in signed format, trying legacy decoding')
		}

		// Legacy format: direct base64 encoded JSON
		try {
			const decodedState = safeBase64Decode(decodedParam)
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
		throw createAuthError('ClientIdExtraction')
	}

	return clientId
}
