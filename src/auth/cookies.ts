import { safeBase64Decode, safeBase64Encode } from '@sudowealth/schwab-api'
import { type ValidatedEnv } from '../../types/env'
import {
	LOGGER_CONTEXTS,
	COOKIE_NAMES,
	HTTP_HEADERS,
} from '../shared/constants'
import { logger } from '../shared/log'
import { sanitizeError } from '../shared/secureLogger'
import { AuthErrors } from './errors'
import { ApprovedClientsSchema } from './schemas'
import { extractClientIdFromState, type StateData } from './stateUtils'

// Create scoped logger for cookie operations
const cookieLogger = logger.child(LOGGER_CONTEXTS.COOKIES)

const MCP_APPROVAL = COOKIE_NAMES.APPROVED_CLIENTS
const ONE_YEAR_IN_SECONDS = 60 * 60 * 24 * 365

// --- Helper Functions ---

/**
 * Converts an ArrayBuffer to a hex string
 * Uses Buffer in Node.js-compatible environments (enabled with nodejs_compat)
 */
function toHex(ab: ArrayBuffer): string {
	return Buffer.from(ab).toString('hex')
}

/**
 * Converts a hex string to an ArrayBuffer
 * Uses Buffer in Node.js-compatible environments (enabled with nodejs_compat)
 *
 * @param hexString - A hexadecimal string
 * @returns ArrayBuffer representation of the hex string
 */
function fromHex(hexString: string): ArrayBuffer {
	// Buffer.from validates hex string format internally
	try {
		return Buffer.from(hexString, 'hex').buffer
	} catch {
		cookieLogger.warn('Invalid hex string format detected', { hexString })
		throw new Error('Invalid hex string format')
	}
}

/**
 * Imports a secret key string for HMAC-SHA256 signing.
 * @param secret - The raw secret key string.
 * @returns A promise resolving to the CryptoKey object.
 */
async function importKey(secret: string): Promise<CryptoKey> {
	if (!secret) {
		throw new AuthErrors.CookieSecretMissing()
	}

	// Validate minimum key length for security (32 characters = 256 bits)
	if (secret.length < 32) {
		throw new Error(
			'Cookie encryption key must be at least 32 characters long for security',
		)
	}

	// Check for basic entropy requirements - ensure it's not all the same character
	const uniqueChars = new Set(secret).size
	if (uniqueChars < 8) {
		throw new Error(
			'Cookie encryption key must have sufficient entropy (at least 8 unique characters)',
		)
	}

	// Warn if key appears to be weak (e.g., simple patterns)
	const isSimplePattern = /^(.)\1*$|^(01|10|abc|123|password|secret)+$/i.test(
		secret,
	)
	if (isSimplePattern) {
		throw new Error(
			'Cookie encryption key appears to use a weak pattern. Use a cryptographically secure random string.',
		)
	}

	// TextEncoder always uses UTF-8 encoding
	const enc = new TextEncoder()
	return crypto.subtle.importKey(
		'raw',
		enc.encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false, // not extractable
		['sign', 'verify'], // key usages
	)
}

/**
 * Signs data using HMAC-SHA256.
 * @param key - The CryptoKey for signing.
 * @param data - The string data to sign.
 * @returns A promise resolving to the signature as a hex string.
 */
async function signData(key: CryptoKey, data: string): Promise<string> {
	// TextEncoder always uses UTF-8 encoding
	const enc = new TextEncoder()
	const signatureBuffer = await crypto.subtle.sign(
		'HMAC',
		key,
		enc.encode(data),
	)
	return toHex(signatureBuffer)
}

/**
 * Verifies an HMAC-SHA256 signature.
 * @param key - The CryptoKey for verification.
 * @param signatureHex - The signature to verify (hex string).
 * @param data - The original data that was signed.
 * @returns A promise resolving to true if the signature is valid, false otherwise.
 */
async function verifySignature(
	key: CryptoKey,
	signatureHex: string,
	data: string,
): Promise<boolean> {
	// TextEncoder always uses UTF-8 encoding
	const enc = new TextEncoder()
	try {
		return await crypto.subtle.verify(
			'HMAC',
			key,
			fromHex(signatureHex),
			enc.encode(data),
		)
	} catch (e) {
		cookieLogger.error('Error verifying signature:', sanitizeError(e))
		return false
	}
}

/**
 * Parses a cookie string and extracts the value of the specified cookie.
 * @param cookieHeader - The raw cookie header string.
 * @param cookieName - The name of the cookie to extract.
 * @returns The cookie value if found, undefined otherwise.
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
 * Verifies and decodes a signed cookie value.
 * Separates signature verification from content parsing for better security.
 *
 * @param cookieValue - The raw cookie value in format "signature.payload".
 * @param secret - The secret key used for signing.
 * @returns A promise resolving to the decoded payload if signature is valid, undefined otherwise.
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

	// TypeScript doesn't know that we've already checked parts.length === 2
	// so we need to assert the types manually
	const signatureHex = parts[0]
	const base64Payload = parts[1]

	// Step 1: Parse the base64 payload to get the raw string
	let payloadString: string
	try {
		// base64Payload must be a string because it comes from parts[1]
		// and we've already checked that parts.length === 2
		if (typeof base64Payload !== 'string') {
			cookieLogger.warn('Invalid base64 payload format: not a string')
			return undefined
		}
		payloadString = safeBase64Decode(base64Payload)
	} catch (e) {
		cookieLogger.warn('Invalid base64 payload in cookie:', sanitizeError(e))
		return undefined
	}

	// Step 2: Verify HMAC signature before parsing JSON
	const key = await importKey(secret)
	if (typeof signatureHex !== 'string') {
		cookieLogger.warn('Invalid signature format: not a string')
		return undefined
	}
	const isValid = await verifySignature(key, signatureHex, payloadString)

	if (!isValid) {
		const error = new AuthErrors.CookieSignature()
		cookieLogger.warn(error.message)
		return undefined
	}

	// Step 3: Parse JSON only after signature validation
	try {
		return JSON.parse(payloadString) as T
	} catch (e) {
		cookieLogger.error('Error parsing cookie payload:', sanitizeError(e))
		return undefined
	}
}

/**
 * Creates a signed cookie string in the format "signature.base64(payload)".
 * @param payload - The data to store in the cookie.
 * @param secret - The secret key used for signing.
 * @returns A promise resolving to the signed cookie value.
 */
async function createSignedCookie(
	payload: any,
	secret: string,
): Promise<string> {
	const stringifiedPayload = JSON.stringify(payload)
	const key = await importKey(secret)
	const signature = await signData(key, stringifiedPayload)
	return `${signature}.${safeBase64Encode(stringifiedPayload, false)}`
}

/**
 * Creates a Set-Cookie header value for the approval cookie.
 * @param cookieValue - The signed cookie value.
 * @returns The Set-Cookie header value.
 */
function createApprovalCookieHeader(cookieValue: string): string {
	return `${MCP_APPROVAL}=${cookieValue}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=${ONE_YEAR_IN_SECONDS}`
}

/**
 * Extracts and validates the approved clients from the cookie.
 * @param cookieHeader - The value of the Cookie header from the request.
 * @param secret - The secret key used for signing.
 * @returns A promise resolving to the list of approved client IDs if the cookie is valid, otherwise undefined.
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
 * @param approvedClients - Array of approved client IDs.
 * @param secret - The secret key used for signing.
 * @returns A promise resolving to the Set-Cookie header value.
 */
async function setApprovalCookie(
	approvedClients: string[],
	secret: string,
): Promise<string> {
	const cookieValue = await createSignedCookie(approvedClients, secret)
	return createApprovalCookieHeader(cookieValue)
}

// --- Exported Functions ---

/**
 * Checks if a given client ID has already been approved by the user,
 * based on a signed cookie.
 *
 * @param request - The incoming Request object to read cookies from.
 * @param clientId - The OAuth client ID to check approval for.
 * @param cookieSecret - The secret key used to sign/verify the approval cookie.
 * @returns A promise resolving to true if the client ID is in the list of approved clients in a valid cookie, false otherwise.
 */
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

/**
 * Result of parsing the approval form submission.
 */
interface ParsedApprovalResult {
	/** The original state object passed through the form. */
	state: StateData
	/** Headers to set on the redirect response, including the Set-Cookie header. */
	headers: Record<string, string>
}

/**
 * Parses the form submission from the approval dialog, extracts the state,
 * and generates Set-Cookie headers to mark the client as approved.
 *
 * @param request - The incoming POST Request object containing the form data.
 * @param config - Validated environment configuration
 * @returns A promise resolving to an object containing the parsed state and necessary headers.
 * @throws If the request method is not POST, form data is invalid, or state is missing.
 */
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

		// The state from the approval form is simple base64-encoded JSON (not EnhancedTokenManager format)
		// This is different from callback states which go through EnhancedTokenManager
		try {
			const decodedStateString = atob(encodedState)
			const parsedState = JSON.parse(decodedStateString)
			state = parsedState as StateData
		} catch (decodeError) {
			cookieLogger.error('Failed to decode approval form state:', {
				error:
					decodeError instanceof Error
						? decodeError.message
						: String(decodeError),
			})
			throw new AuthErrors.InvalidState()
		}

		clientId = extractClientIdFromState(state)
	} catch (e) {
		cookieLogger.error('Error processing form submission:', sanitizeError(e))
		// Rethrow with centralized error format
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

	// Return result with headers
	return {
		state,
		headers: { [HTTP_HEADERS.SET_COOKIE]: cookieHeaderValue },
	}
}
