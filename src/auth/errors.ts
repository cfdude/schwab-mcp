// Auth error definitions simplified using discriminated unions
import { logger, LogLevel } from '../shared/logger'

export type AuthErrorKind =
	| 'MissingClientId'
	| 'MissingState'
	| 'MissingParameters'
	| 'InvalidState'
	| 'CookieDecode'
	| 'InvalidCookieFormat'
	| 'InvalidRequestMethod'
	| 'MissingFormState'
	| 'ClientIdExtraction'
	| 'CookieSignature'
	| 'AuthRequest'
	| 'AuthApproval'
	| 'AuthCallback'
	| 'AuthUrl'
	| 'NoUserId'
	| 'TokenExchange'
	| 'ApiResponse'
	| 'CookieSecretMissing'

export interface AuthError {
	kind: AuthErrorKind
	status: number
	message: string
	cause?: Error
}

const ERROR_DEFS: Record<AuthErrorKind, { status: number; message: string }> = {
	MissingClientId: {
		status: 400,
		message: 'Invalid request: clientId is missing',
	},
	MissingState: {
		status: 400,
		message: 'Invalid request: state.oauthReqInfo is missing',
	},
	MissingParameters: { status: 400, message: 'Missing required parameters' },
	InvalidState: { status: 400, message: 'Invalid state: clientId is missing' },
	CookieDecode: { status: 400, message: 'Could not decode state' },
	InvalidCookieFormat: {
		status: 400,
		message: 'Invalid cookie format received',
	},
	InvalidRequestMethod: {
		status: 400,
		message: 'Invalid request method. Expected POST.',
	},
	MissingFormState: {
		status: 400,
		message: "Missing or invalid 'state' in form data.",
	},
	ClientIdExtraction: {
		status: 400,
		message: 'Could not extract clientId from state object.',
	},
	CookieSignature: {
		status: 401,
		message: 'Cookie signature verification failed',
	},
	AuthRequest: {
		status: 500,
		message: 'Error processing authorization request',
	},
	AuthApproval: { status: 500, message: 'Error processing approval' },
	AuthCallback: {
		status: 500,
		message: 'Authorization failed during callback processing',
	},
	AuthUrl: { status: 500, message: 'Error creating authorization URL' },
	NoUserId: {
		status: 500,
		message: 'Failed to retrieve user information after Schwab auth',
	},
	TokenExchange: {
		status: 500,
		message: 'Failed to exchange Schwab authorization code for tokens',
	},
	ApiResponse: {
		status: 500,
		message: 'Schwab API request failed during authorization flow',
	},
	CookieSecretMissing: {
		status: 500,
		message:
			'COOKIE_SECRET is not defined. A secret key is required for signing cookies.',
	},
}

export function createAuthError(kind: AuthErrorKind, cause?: Error): AuthError {
	const def = ERROR_DEFS[kind]
	return {
		kind,
		status: def.status,
		message: def.message,
		...(cause ? { cause } : {}),
	}
}

export interface JsonErrorResponse {
	code: string
	message: string
	requestId?: string
	details?: Record<string, any>
}

interface ErrorResponse {
	message: string
	status: number
	details?: any
}

export function formatAuthError(
	error: AuthError,
	details?: Record<string, any>,
): ErrorResponse {
	const includeStack = logger.getLevel() === LogLevel.DEBUG
	let filtered = details
	if (details && !includeStack) {
		const { stack, ...rest } = details
		filtered = rest
	}
	return {
		message: error.message,
		status: error.status,
		...(filtered && { details: filtered }),
	}
}

export function createJsonErrorResponse(
	error: AuthError,
	requestId?: string,
	additionalDetails?: Record<string, any>,
): JsonErrorResponse {
	return {
		code: error.kind,
		message: error.message,
		...(requestId && { requestId }),
		...(additionalDetails && { details: additionalDetails }),
	}
}
