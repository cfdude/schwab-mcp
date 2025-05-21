/**
 * Centralized error message constants for auth-related operations
 *
 * This file contains standardized error messages to ensure consistency
 * across the auth module and to make error handling more maintainable.
 */

// General auth errors
export enum AuthError {
	// Client errors (400 series)
	MISSING_CLIENT_ID = 'Invalid request: clientId is missing',
	MISSING_STATE = 'Invalid request: state.oauthReqInfo is missing',
	MISSING_PARAMETERS = 'Missing required parameters',
	INVALID_STATE = 'Invalid state: clientId is missing',

	// Server errors (500 series)
	AUTH_REQUEST_ERROR = 'Error processing authorization request',
	AUTH_APPROVAL_ERROR = 'Error processing approval',
	AUTH_CALLBACK_ERROR = 'Authorization failed',
	AUTH_URL_ERROR = 'Error creating authorization URL',
	NO_USER_ID = 'Failed to retrieve user information',
	TOKEN_EXCHANGE_ERROR = 'Failed to exchange authorization code for tokens',
	API_RESPONSE_ERROR = 'API request failed during authorization',
	USER_INFO_ERROR = 'Failed to retrieve user identification information',

	// Token errors
	TOKEN_LOAD_ERROR = 'Error loading token data',
	TOKEN_SAVE_ERROR = 'Error saving token data',
	TOKEN_REFRESH_ERROR = 'Error refreshing token',
	TOKEN_VALIDATION_ERROR = 'Error validating token',

	// Cookie errors
	COOKIE_SECRET_MISSING = 'COOKIE_SECRET is not defined. A secret key is required for signing cookies.',
	COOKIE_DECODE_ERROR = 'Could not decode state',
	INVALID_COOKIE_FORMAT = 'Invalid cookie format received',
	COOKIE_SIGNATURE_FAILED = 'Cookie signature verification failed',

	// Form errors
	INVALID_REQUEST_METHOD = 'Invalid request method. Expected POST.',
	MISSING_FORM_STATE = "Missing or invalid 'state' in form data.",
	CLIENT_ID_EXTRACTION_ERROR = 'Could not extract clientId from state object.',
}

// HTTP status codes associated with errors
export enum StatusCode {
	BAD_REQUEST = 400,
	UNAUTHORIZED = 401,
	FORBIDDEN = 403,
	NOT_FOUND = 404,
	SERVER_ERROR = 500,
}

/**
 * Maps error types to appropriate HTTP status codes
 */
export const errorStatusMap: Record<AuthError, StatusCode> = {
	[AuthError.MISSING_CLIENT_ID]: StatusCode.BAD_REQUEST,
	[AuthError.MISSING_STATE]: StatusCode.BAD_REQUEST,
	[AuthError.MISSING_PARAMETERS]: StatusCode.BAD_REQUEST,
	[AuthError.INVALID_STATE]: StatusCode.BAD_REQUEST,
	[AuthError.AUTH_REQUEST_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.AUTH_APPROVAL_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.AUTH_CALLBACK_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.AUTH_URL_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.NO_USER_ID]: StatusCode.SERVER_ERROR,
	[AuthError.TOKEN_EXCHANGE_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.API_RESPONSE_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.USER_INFO_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.TOKEN_LOAD_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.TOKEN_SAVE_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.TOKEN_REFRESH_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.TOKEN_VALIDATION_ERROR]: StatusCode.SERVER_ERROR,
	[AuthError.COOKIE_SECRET_MISSING]: StatusCode.SERVER_ERROR,
	[AuthError.COOKIE_DECODE_ERROR]: StatusCode.BAD_REQUEST,
	[AuthError.INVALID_COOKIE_FORMAT]: StatusCode.BAD_REQUEST,
	[AuthError.COOKIE_SIGNATURE_FAILED]: StatusCode.UNAUTHORIZED,
	[AuthError.INVALID_REQUEST_METHOD]: StatusCode.BAD_REQUEST,
	[AuthError.MISSING_FORM_STATE]: StatusCode.BAD_REQUEST,
	[AuthError.CLIENT_ID_EXTRACTION_ERROR]: StatusCode.BAD_REQUEST,
}

/**
 * Formats an error response with appropriate logging
 *
 * @param error The error enum value or custom message
 * @param details Optional additional details for debugging
 * @param status Optional status code override
 * @returns A standardized error response object
 */
export interface ErrorResponse {
	message: string
	status: StatusCode
	details?: any
}

export function formatAuthError(
	error: AuthError | string,
	details?: any,
	status?: StatusCode,
): ErrorResponse {
	// If the error is a predefined enum value, use its mapped status code
	const message = error
	const statusCode =
		status ||
		(error in AuthError
			? errorStatusMap[error as AuthError]
			: StatusCode.SERVER_ERROR)

	return {
		message,
		status: statusCode,
		details,
	}
}
