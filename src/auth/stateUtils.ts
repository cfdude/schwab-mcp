import { type AuthRequest } from '@cloudflare/workers-oauth-provider'
import { logger } from '../shared/logger'
import { AuthError, formatAuthError } from './errorMessages'

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

/**
 * Encodes a state object to base64.
 *
 * @param state - The state object to encode.
 * @returns The base64 encoded state string.
 */
export function encodeState(state: StateData): string {
	const jsonString = JSON.stringify(state)
	return btoa(jsonString)
}
