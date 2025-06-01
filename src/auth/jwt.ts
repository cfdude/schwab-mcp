import { LOGGER_CONTEXTS } from '../shared/constants'
import { logger } from '../shared/log'

const jwtLogger = logger.child(LOGGER_CONTEXTS.JWT)

interface JWTHeader {
	alg: 'HS256'
	typ: 'JWT'
}

interface JWTPayload {
	iat: number
	exp: number
	[key: string]: any
}

function base64UrlEncode(data: string | Uint8Array): string {
	const base64 =
		typeof data === 'string'
			? btoa(data)
			: btoa(String.fromCharCode(...Array.from(data)))
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function base64UrlDecode(str: string): string {
	const base64 = str.replace(/-/g, '+').replace(/_/g, '/')
	const padding = base64.length % 4
	const padded = padding ? base64 + '='.repeat(4 - padding) : base64
	return atob(padded)
}

async function createHmacSignature(
	message: string,
	secret: string,
): Promise<string> {
	const encoder = new TextEncoder()
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign'],
	)

	const signature = await crypto.subtle.sign(
		'HMAC',
		key,
		encoder.encode(message),
	)
	return base64UrlEncode(new Uint8Array(signature))
}

async function verifyHmacSignature(
	message: string,
	signature: string,
	secret: string,
): Promise<boolean> {
	const encoder = new TextEncoder()
	const key = await crypto.subtle.importKey(
		'raw',
		encoder.encode(secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['verify'],
	)

	try {
		const signatureBytes = Uint8Array.from(
			atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
			(c) => c.charCodeAt(0),
		)

		return await crypto.subtle.verify(
			'HMAC',
			key,
			signatureBytes,
			encoder.encode(message),
		)
	} catch (e) {
		jwtLogger.error('[ERROR] Error verifying HMAC signature:', e)
		return false
	}
}

export async function sign<T extends Record<string, any>>(
	secret: string,
	payload: T,
): Promise<string> {
	const header: JWTHeader = { alg: 'HS256', typ: 'JWT' }
	const now = Math.floor(Date.now() / 1000)

	const jwtPayload: JWTPayload = {
		...payload,
		iat: now,
		exp: now + 300, // 5 minutes expiry
	}

	const headerEncoded = base64UrlEncode(JSON.stringify(header))
	const payloadEncoded = base64UrlEncode(JSON.stringify(jwtPayload))
	const message = `${headerEncoded}.${payloadEncoded}`

	const signature = await createHmacSignature(message, secret)

	return `${message}.${signature}`
}

export async function verify<T extends Record<string, any>>(
	secret: string,
	token: string,
): Promise<T> {
	const parts = token.split('.')
	if (parts.length !== 3) {
		throw new Error('Invalid JWT format')
	}

	const [headerEncoded, payloadEncoded, signature] = parts
	if (!headerEncoded || !payloadEncoded || !signature) {
		throw new Error('Invalid JWT format: missing parts')
	}

	const message = `${headerEncoded}.${payloadEncoded}`

	// Verify signature
	const isValid = await verifyHmacSignature(message, signature, secret)
	if (!isValid) {
		throw new Error('Invalid JWT signature')
	}

	// Decode and verify header
	const header = JSON.parse(base64UrlDecode(headerEncoded)) as JWTHeader
	if (header.alg !== 'HS256' || header.typ !== 'JWT') {
		throw new Error('Invalid JWT header')
	}

	// Decode payload
	const payload = JSON.parse(base64UrlDecode(payloadEncoded)) as JWTPayload

	// Check expiration
	const now = Math.floor(Date.now() / 1000)
	if (payload.exp && payload.exp < now) {
		throw new Error('JWT has expired')
	}

	// Remove JWT-specific claims and return the original payload
	const { iat, exp, ...originalPayload } = payload
	return originalPayload as T
}
