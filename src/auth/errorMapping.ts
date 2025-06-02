import {
	AuthErrorCode as SchwabSDKAuthErrorCode,
	SchwabErrorMapper,
} from '@sudowealth/schwab-api'
import { AuthErrors, type AuthError } from './errors'

// Create instance with MCP-specific mappings
const errorMapper = new SchwabErrorMapper({
	customAuthMappings: {
		// Add any MCP-specific error mappings here if needed
	},
})

/**
 * Maps a Schwab SDK error to the appropriate MCP error and metadata
 * This is a thin wrapper around the SDK's error mapper
 */
export function mapSchwabError(
	code: SchwabSDKAuthErrorCode,
	originalMessage: string,
	schwabStatus?: number,
): {
	mcpError: AuthError
	detailMessage: string
	httpStatus: number
} {
	// Create a mock error object for the mapper
	const mockError = {
		code,
		message: originalMessage,
		status: schwabStatus,
		isRetryable: () => false, // Will be determined by mapping
	} as any

	const mapping = errorMapper.mapAuthError(mockError)

	// Map the SDK error code to MCP error class
	const mcpErrorMap: Record<string, () => AuthError> = {
		[SchwabSDKAuthErrorCode.INVALID_CODE]: () => new AuthErrors.TokenExchange(),
		[SchwabSDKAuthErrorCode.PKCE_VERIFIER_MISSING]: () =>
			new AuthErrors.TokenExchange(),
		[SchwabSDKAuthErrorCode.TOKEN_EXPIRED]: () =>
			new AuthErrors.TokenExchange(),
		[SchwabSDKAuthErrorCode.UNAUTHORIZED]: () => new AuthErrors.TokenExchange(),
		[SchwabSDKAuthErrorCode.TOKEN_PERSISTENCE_LOAD_FAILED]: () =>
			new AuthErrors.AuthCallback(),
		[SchwabSDKAuthErrorCode.TOKEN_PERSISTENCE_SAVE_FAILED]: () =>
			new AuthErrors.AuthCallback(),
		[SchwabSDKAuthErrorCode.TOKEN_VALIDATION_ERROR]: () =>
			new AuthErrors.AuthCallback(),
		[SchwabSDKAuthErrorCode.TOKEN_ENDPOINT_CONFIG_ERROR]: () =>
			new AuthErrors.AuthCallback(),
		[SchwabSDKAuthErrorCode.REFRESH_NEEDED]: () => new AuthErrors.ApiResponse(),
		[SchwabSDKAuthErrorCode.NETWORK]: () => new AuthErrors.ApiResponse(),
		[SchwabSDKAuthErrorCode.UNKNOWN]: () => new AuthErrors.AuthCallback(),
	}

	const mcpErrorFactory =
		mcpErrorMap[code] || (() => new AuthErrors.AuthCallback())

	return {
		mcpError: mcpErrorFactory(),
		detailMessage: mapping.message,
		httpStatus: mapping.httpStatus,
	}
}
