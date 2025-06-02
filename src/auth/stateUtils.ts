import { type AuthRequest } from '@cloudflare/workers-oauth-provider'
import {
	decodeAndVerifyState as sdkDecodeAndVerifyState,
	extractClientIdFromState as sdkExtractClientIdFromState,
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
 * This is now a thin wrapper around the SDK's enhanced function
 */
export async function decodeAndVerifyState<T = AuthRequest>(
	config: ValidatedEnv,
	stateParam: string,
): Promise<T | null> {
	try {
		// Use SDK's enhanced decode and verify function
		const decoded = sdkDecodeAndVerifyState<T>(stateParam, {
			schema: StateSchema as any, // MCP-specific schema
			requiredFields: ['clientId'], // MCP requires clientId
		})

		if (!decoded) {
			stateLogger.error('Failed to decode state parameter')
			return null
		}

		// Check for required OAuth fields specific to MCP
		const authRequest = decoded as any
		if (authRequest.responseType && authRequest.clientId) {
			stateLogger.debug('Processing valid OAuth state')
			return decoded
		}

		stateLogger.error('Missing required OAuth fields in state')
		return null
	} catch (error) {
		stateLogger.error('[ERROR] Error decoding state:', error)
		return null
	}
}

/**
 * Extracts the client ID from a state object
 * Delegates to SDK implementation
 */
export function extractClientIdFromState(
	state: StateData | AuthRequest,
): string {
	const clientId = sdkExtractClientIdFromState(state)

	if (!clientId) {
		throw new AuthErrors.ClientIdExtraction()
	}

	return clientId
}
