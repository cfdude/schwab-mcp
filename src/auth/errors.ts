/**
 * Custom error classes for auth module with built-in status codes
 *
 * These error classes extend Error and include HTTP status codes as properties,
 * eliminating the need for separate mapping tables.
 */

// Base auth error class
export class AuthError extends Error {
	status: number

	constructor(message: string, status = 500) {
		super(message)
		this.name = this.constructor.name
		this.status = status
		// Maintain proper stack trace in V8
		if (Error.captureStackTrace) {
			Error.captureStackTrace(this, this.constructor)
		}
	}
}

// Client errors (400 series)
export class MissingClientIdError extends AuthError {
	constructor() {
		super('Invalid request: clientId is missing', 400)
	}
}

export class MissingStateError extends AuthError {
	constructor() {
		super('Invalid request: state.oauthReqInfo is missing', 400)
	}
}

export class MissingParametersError extends AuthError {
	constructor() {
		super('Missing required parameters', 400)
	}
}

export class InvalidStateError extends AuthError {
	constructor() {
		super('Invalid state: clientId is missing', 400)
	}
}

export class CookieDecodeError extends AuthError {
	constructor() {
		super('Could not decode state', 400)
	}
}

export class InvalidCookieFormatError extends AuthError {
	constructor() {
		super('Invalid cookie format received', 400)
	}
}

export class InvalidRequestMethodError extends AuthError {
	constructor() {
		super('Invalid request method. Expected POST.', 400)
	}
}

export class MissingFormStateError extends AuthError {
	constructor() {
		super("Missing or invalid 'state' in form data.", 400)
	}
}

export class ClientIdExtractionError extends AuthError {
	constructor() {
		super('Could not extract clientId from state object.', 400)
	}
}

// Unauthorized errors (401)
export class CookieSignatureError extends AuthError {
	constructor() {
		super('Cookie signature verification failed', 401)
	}
}

// Server errors (500 series)
export class AuthRequestError extends AuthError {
	constructor() {
		super('Error processing authorization request', 500)
	}
}

export class AuthApprovalError extends AuthError {
	constructor() {
		super('Error processing approval', 500)
	}
}

export class AuthCallbackError extends AuthError {
	constructor() {
		super('Authorization failed during callback processing', 500)
	}
}

export class AuthUrlError extends AuthError {
	constructor() {
		super('Error creating authorization URL', 500)
	}
}

export class NoUserIdError extends AuthError {
	constructor() {
		super('Failed to retrieve user information after Schwab auth', 500)
	}
}

export class TokenExchangeError extends AuthError {
	constructor() {
		super('Failed to exchange Schwab authorization code for tokens', 500)
	}
}

export class ApiResponseError extends AuthError {
	constructor() {
		super('Schwab API request failed during authorization flow', 500)
	}
}

export class CookieSecretMissingError extends AuthError {
	constructor() {
		super(
			'COOKIE_SECRET is not defined. A secret key is required for signing cookies.',
			500,
		)
	}
}

/**
 * Formats an error response with appropriate logging
 * Now simplified to work with Error objects that have status property
 *
 * @param error The error object
 * @param details Optional additional details for debugging
 * @returns A standardized error response object
 */
interface ErrorResponse {
	message: string
	status: number
	details?: any
}

export function formatAuthError(
	error: Error & { status?: number },
	details?: any,
): ErrorResponse {
	return {
		message: error.message,
		status: error.status ?? 500,
		details,
	}
}
