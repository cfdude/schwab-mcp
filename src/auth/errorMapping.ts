import { AuthErrorCode as SchwabSDKAuthErrorCode } from '@sudowealth/schwab-api'
import { AuthErrors, type AuthError } from './errors'

interface ErrorMapping {
	mcpError: () => AuthError
	message: (originalMessage: string) => string
	httpStatus: number
}

/**
 * Maps Schwab SDK error codes to MCP error classes and metadata
 * This replaces the large switch statement with a cleaner lookup table
 */
const schwabErrorMap: Record<SchwabSDKAuthErrorCode, ErrorMapping> = {
	[SchwabSDKAuthErrorCode.INVALID_CODE]: {
		mcpError: () => new AuthErrors.TokenExchange(),
		message: (msg) =>
			`Token exchange failed: Invalid authorization code or PKCE issue. Details: ${msg}`,
		httpStatus: 400,
	},
	[SchwabSDKAuthErrorCode.PKCE_VERIFIER_MISSING]: {
		mcpError: () => new AuthErrors.TokenExchange(),
		message: (msg) =>
			`Token exchange failed: Invalid authorization code or PKCE issue. Details: ${msg}`,
		httpStatus: 400,
	},
	[SchwabSDKAuthErrorCode.TOKEN_EXPIRED]: {
		mcpError: () => new AuthErrors.TokenExchange(),
		message: (msg) =>
			`Token operation failed: Token expired, re-authentication required. Details: ${msg}`,
		httpStatus: 401,
	},
	[SchwabSDKAuthErrorCode.UNAUTHORIZED]: {
		mcpError: () => new AuthErrors.TokenExchange(),
		message: (msg) =>
			`Authorization failed: Client unauthorized or invalid credentials. Details: ${msg}`,
		httpStatus: 401,
	},
	[SchwabSDKAuthErrorCode.TOKEN_PERSISTENCE_LOAD_FAILED]: {
		mcpError: () => new AuthErrors.AuthCallback(),
		message: (msg) =>
			`Critical: Failed to load token data during authorization. Details: ${msg}`,
		httpStatus: 500,
	},
	[SchwabSDKAuthErrorCode.TOKEN_PERSISTENCE_SAVE_FAILED]: {
		mcpError: () => new AuthErrors.AuthCallback(),
		message: (msg) =>
			`Critical: Failed to save token data during authorization. Details: ${msg}`,
		httpStatus: 500,
	},
	[SchwabSDKAuthErrorCode.TOKEN_VALIDATION_ERROR]: {
		mcpError: () => new AuthErrors.AuthCallback(),
		message: (msg) =>
			`Critical: Token validation failed during authorization. Details: ${msg}`,
		httpStatus: 500,
	},
	[SchwabSDKAuthErrorCode.TOKEN_ENDPOINT_CONFIG_ERROR]: {
		mcpError: () => new AuthErrors.AuthCallback(),
		message: (msg) =>
			`Critical: Auth system configuration error. Details: ${msg}`,
		httpStatus: 500,
	},
	[SchwabSDKAuthErrorCode.REFRESH_NEEDED]: {
		mcpError: () => new AuthErrors.ApiResponse(),
		message: (msg) => `Failed to refresh token during API call: ${msg}`,
		httpStatus: 500,
	},
	[SchwabSDKAuthErrorCode.NETWORK]: {
		mcpError: () => new AuthErrors.ApiResponse(),
		message: (msg) => `Network error during authentication: ${msg}`,
		httpStatus: 503,
	},
	[SchwabSDKAuthErrorCode.UNKNOWN]: {
		mcpError: () => new AuthErrors.AuthCallback(),
		message: (msg) => `Unknown authentication error: ${msg}`,
		httpStatus: 500,
	},
}

/**
 * Maps a Schwab SDK error to the appropriate MCP error and metadata
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
	const mapping = schwabErrorMap[code]

	if (!mapping) {
		// Default fallback for unmapped codes
		return {
			mcpError: new AuthErrors.AuthCallback(),
			detailMessage: `An authentication error occurred: ${originalMessage}`,
			httpStatus: schwabStatus || 500,
		}
	}

	return {
		mcpError: mapping.mcpError(),
		detailMessage: mapping.message(originalMessage),
		httpStatus: schwabStatus || mapping.httpStatus,
	}
}
