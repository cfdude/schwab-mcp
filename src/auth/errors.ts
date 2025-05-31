// Auth error definitions simplified using discriminated unions
import { logger, LogLevel as AppLogLevel } from '../shared/logger'

type AuthErrorKind =
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

/**
 * Factory function that provides error definitions for each AuthErrorKind
 * This ensures compile-time coverage - the TypeScript compiler will fail
 * if a new AuthErrorKind is added but not handled in the switch statement
 */
function errorDef(kind: AuthErrorKind): { status: number; message: string } {
	switch (kind) {
		case 'MissingClientId':
			return {
				status: 400,
				message: 'Invalid request: clientId is missing',
			}
		case 'MissingState':
			return {
				status: 400,
				message: 'Invalid request: state.oauthReqInfo is missing',
			}
		case 'MissingParameters':
			return { status: 400, message: 'Missing required parameters' }
		case 'InvalidState':
			return { status: 400, message: 'Invalid state: clientId is missing' }
		case 'CookieDecode':
			return { status: 400, message: 'Could not decode state' }
		case 'InvalidCookieFormat':
			return {
				status: 400,
				message: 'Invalid cookie format received',
			}
		case 'InvalidRequestMethod':
			return {
				status: 400,
				message: 'Invalid request method. Expected POST.',
			}
		case 'MissingFormState':
			return {
				status: 400,
				message: "Missing or invalid 'state' in form data.",
			}
		case 'ClientIdExtraction':
			return {
				status: 400,
				message: 'Could not extract clientId from state object.',
			}
		case 'CookieSignature':
			return {
				status: 401,
				message: 'Cookie signature verification failed',
			}
		case 'AuthRequest':
			return {
				status: 500,
				message: 'Error processing authorization request',
			}
		case 'AuthApproval':
			return { status: 500, message: 'Error processing approval' }
		case 'AuthCallback':
			return {
				status: 500,
				message: 'Authorization failed during callback processing',
			}
		case 'AuthUrl':
			return { status: 500, message: 'Error creating authorization URL' }
		case 'NoUserId':
			return {
				status: 500,
				message: 'Failed to retrieve user information after Schwab auth',
			}
		case 'TokenExchange':
			return {
				status: 500,
				message: 'Failed to exchange Schwab authorization code for tokens',
			}
		case 'ApiResponse':
			return {
				status: 500,
				message: 'Schwab API request failed during authorization flow',
			}
		case 'CookieSecretMissing':
			return {
				status: 500,
				message:
					'COOKIE_SECRET is not defined. A secret key is required for signing cookies.',
			}
		default:
			// This ensures exhaustive checking - TypeScript will error if a case is missing
			const _exhaustiveCheck: never = kind
			return _exhaustiveCheck
	}
}

export function createAuthError(kind: AuthErrorKind, cause?: Error): AuthError {
	const def = errorDef(kind)
	return {
		kind,
		status: def.status,
		message: def.message,
		...(cause ? { cause } : {}),
	}
}

interface JsonErrorResponse {
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
	const includeStack = logger.getLevel() === AppLogLevel.Debug
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
