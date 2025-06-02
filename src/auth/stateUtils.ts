import { type AuthRequest } from '@cloudflare/workers-oauth-provider'
import {
	decodeOAuthState,
	validateOAuthState,
	sanitizeError,
} from '@sudowealth/schwab-api'
import { type ValidatedEnv } from '../../types/env'
import { LOGGER_CONTEXTS } from '../shared/constants'
import { logger } from '../shared/log'
import { AuthErrors } from './errors'
import { StateSchema, type StateData as StateDataFromSchema } from './schemas'

// Create scoped logger for OAuth state operations
const stateLogger = logger.child(LOGGER_CONTEXTS.STATE_UTILS)

// Re-export StateData type from schemas
export type StateData = StateDataFromSchema

/**
 * Decodes and verifies a state parameter from OAuth callback.
 * This wraps the SDK's decodeOAuthState with MCP-specific validation
 */
export async function decodeAndVerifyState<T = AuthRequest>(
	config: ValidatedEnv,
	stateParam: string,
): Promise<T | null> {
	try {
		// Use SDK's decode function
		const decoded = decodeOAuthState<T>(stateParam)

		if (!decoded) {
			stateLogger.error('Failed to decode state parameter')
			return null
		}

		// Validate against MCP's schema
		if (!validateOAuthState(decoded, StateSchema)) {
			stateLogger.error('State validation failed against schema')
			return null
		}

		// Check for required OAuth fields
		const authRequest = decoded as any
		if (authRequest.responseType && authRequest.clientId) {
			stateLogger.debug('Processing valid OAuth state')
			return decoded
		}

		stateLogger.error('Missing required OAuth fields in state')
		return null
	} catch (error) {
		stateLogger.error('[ERROR] Error decoding state:', sanitizeError(error))
		return null
	}
}

/**
 * Extracts the client ID from a state object
 * This remains MCP-specific as it handles the local state structure
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
