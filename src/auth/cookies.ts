import {
	decodeOAuthState,
	createHmacKey,
	signData,
	verifySignature,
	sanitizeError,
} from '@sudowealth/schwab-api'
import { type ValidatedEnv } from '../../types/env'
import {
	LOGGER_CONTEXTS,
	COOKIE_NAMES,
	HTTP_HEADERS,
} from '../shared/constants'
import { logger } from '../shared/log'
import { AuthErrors } from './errors'
import { ApprovedClientsSchema } from './schemas'
import { extractClientIdFromState, type StateData } from './stateUtils'

// Create scoped logger for cookie operations
const cookieLogger = logger.child(LOGGER_CONTEXTS.COOKIES)

const MCP_APPROVAL = COOKIE_NAMES.APPROVED_CLIENTS
const ONE_YEAR_IN_SECONDS = 60 * 60 * 24 * 365

// --- Cookie-specific functions ---

/**
 * Creates a signed cookie string in the format "signature.base64(payload)".
 * Uses SDK crypto utilities
 */
async function createSignedCookie(
	payload: any,
	secret: string,
): Promise<string> {
	const stringifiedPayload = JSON.stringify(payload)
	const key = await createHmacKey(secret)
	const signature = await signData(key, stringifiedPayload)

	// Simple base64 encoding for the payload
	const base64Payload = Buffer.from(stringifiedPayload).toString('base64')
	return `${signature}.${base64Payload}`
}

/**
 * Verifies and decodes a signed cookie value.
 * Uses SDK crypto utilities
 */
async function verifyAndDecodeCookie<T>(
	cookieValue: string | undefined,
	secret: string,
): Promise<T | undefined> {
	if (!cookieValue) return undefined

	const parts = cookieValue.split('.')
	if (parts.length !== 2) {
		const error = new AuthErrors.InvalidCookieFormat()
		cookieLogger.warn(error.message)
		return undefined
	}

	const [signatureHex, base64Payload] = parts

	// Decode the payload
	let payloadString: string
	try {
		payloadString = Buffer.from(base64Payload!, 'base64').toString('utf-8')
	} catch (e) {
		cookieLogger.warn('Invalid base64 payload in cookie:', sanitizeError(e))
		return undefined
	}

	// Verify signature using SDK utilities
	const key = await createHmacKey(secret)
	const isValid = await verifySignature(key, signatureHex!, payloadString)

	if (!isValid) {
		const error = new AuthErrors.CookieSignature()
		cookieLogger.warn(error.message)
		return undefined
	}

	// Parse JSON
	try {
		return JSON.parse(payloadString) as T
	} catch (e) {
		cookieLogger.error('Error parsing cookie payload:', sanitizeError(e))
		return undefined
	}
}

/**
 * Parses a cookie string and extracts the value of the specified cookie.
 */
function extractCookieValue(
	cookieHeader: string | null,
	cookieName: string,
): string | undefined {
	if (!cookieHeader) return undefined

	const cookies = cookieHeader.split(';').map((c) => c.trim())
	const targetCookie = cookies.find((c) => c.startsWith(`${cookieName}=`))

	if (!targetCookie) return undefined
	return targetCookie.substring(cookieName.length + 1)
}

/**
 * Creates a Set-Cookie header value for the approval cookie.
 */
function createApprovalCookieHeader(cookieValue: string): string {
	return `${MCP_APPROVAL}=${cookieValue}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=${ONE_YEAR_IN_SECONDS}`
}

/**
 * Extracts and validates the approved clients from the cookie.
 */
async function parseApprovalCookie(
	cookieHeader: string | null,
	secret: string,
): Promise<string[] | undefined> {
	const cookieValue = extractCookieValue(cookieHeader, MCP_APPROVAL)
	const approvedClients = await verifyAndDecodeCookie<string[]>(
		cookieValue,
		secret,
	)

	// Validate with Zod schema
	if (approvedClients) {
		try {
			return ApprovedClientsSchema.parse(approvedClients)
		} catch (e) {
			cookieLogger.warn('Cookie payload validation failed:', sanitizeError(e))
			return undefined
		}
	}

	return approvedClients
}

/**
 * Sets the approval cookie with the provided client IDs.
 */
async function setApprovalCookie(
	approvedClients: string[],
	secret: string,
): Promise<string> {
	const cookieValue = await createSignedCookie(approvedClients, secret)
	return createApprovalCookieHeader(cookieValue)
}

// --- Exported Functions (remain the same) ---

export async function clientIdAlreadyApproved(
	request: Request,
	clientId: string,
	cookieSecret: string,
): Promise<boolean> {
	if (!clientId) return false
	const cookieHeader = request.headers.get('Cookie')
	const approvedClients = await parseApprovalCookie(cookieHeader, cookieSecret)

	return approvedClients?.includes(clientId) ?? false
}

export interface ParsedApprovalResult {
	state: StateData
	headers: Record<string, string>
}

export async function parseRedirectApproval(
	request: Request,
	config: ValidatedEnv,
): Promise<ParsedApprovalResult> {
	const cookieSecret = config.COOKIE_ENCRYPTION_KEY
	if (request.method !== 'POST') {
		throw new AuthErrors.InvalidRequestMethod()
	}

	let encodedState: string
	let state: StateData
	let clientId: string

	try {
		const formData = await request.formData()
		const stateParam = formData.get('state')

		if (typeof stateParam !== 'string' || !stateParam) {
			throw new AuthErrors.MissingFormState()
		}

		encodedState = stateParam

		// Use SDK's OAuth state decoder
		const decodedState = decodeOAuthState<StateData>(encodedState)
		if (!decodedState) {
			throw new AuthErrors.InvalidState()
		}

		state = decodedState
		clientId = extractClientIdFromState(state)
	} catch (e) {
		cookieLogger.error('Error processing form submission:', sanitizeError(e))
		throw new Error(
			`Failed to parse approval form: ${e instanceof Error ? e.message : String(e)}`,
		)
	}

	// Get existing approved clients
	const cookieHeader = request.headers.get('Cookie')
	const existingApprovedClients =
		(await parseApprovalCookie(cookieHeader, cookieSecret)) ?? []

	// Add the newly approved client ID (avoid duplicates)
	const updatedApprovedClients = Array.from(
		new Set([...existingApprovedClients, clientId]),
	)

	// Create the Set-Cookie header
	const cookieHeaderValue = await setApprovalCookie(
		updatedApprovedClients,
		cookieSecret,
	)

	return {
		state,
		headers: { [HTTP_HEADERS.SET_COOKIE]: cookieHeaderValue },
	}
}
