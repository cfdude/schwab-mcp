import jwt from '@tsndr/cloudflare-worker-jwt'
import { LOGGER_CONTEXTS } from '../../shared/constants'
import { logger } from '../../shared/log'
import { sanitizeError } from '../../shared/secureLogger'

const jwtLogger = logger.child(LOGGER_CONTEXTS.JWT)

type StateTokenPayload<T = Record<string, unknown>> = T & {
	iat?: number
	exp?: number
}

/**
 * Signs a state payload with the provided secret using HS256 algorithm
 * @param secret - The secret key for signing
 * @param payload - The state payload to sign
 * @param expiresIn - Token expiry in seconds (configurable via JWT_STATE_EXPIRATION_SECONDS)
 * @returns JWT token string
 */
export async function signState<T extends Record<string, unknown>>(
	secret: string,
	payload: T,
	expiresIn = 300,
): Promise<string> {
	const now = Math.floor(Date.now() / 1000)

	const tokenPayload: StateTokenPayload<T> = {
		...payload,
		iat: now,
		exp: now + expiresIn,
	}

	try {
		return await jwt.sign(tokenPayload, secret)
	} catch (error) {
		jwtLogger.error('[ERROR] Error signing JWT:', sanitizeError(error))
		throw new Error('Failed to sign JWT')
	}
}

/**
 * Verifies a JWT token and returns the decoded payload
 * @param secret - The secret key for verification
 * @param token - The JWT token to verify
 * @returns The decoded payload without JWT-specific claims
 * @throws Error if verification fails or token is expired
 */
export async function verifyState<T extends Record<string, unknown>>(
	secret: string,
	token: string,
): Promise<T> {
	try {
		// @tsndr/cloudflare-worker-jwt handles signature verification and expiry checking
		const isValid = await jwt.verify(token, secret)

		if (!isValid) {
			throw new Error('Invalid JWT')
		}

		const decoded = jwt.decode(token)

		if (!decoded || !decoded.payload || typeof decoded.payload !== 'object') {
			throw new Error('Invalid JWT payload')
		}

		// Check expiration manually since decode doesn't verify it
		const now = Math.floor(Date.now() / 1000)
		if (decoded.payload.exp && decoded.payload.exp < now) {
			throw new Error('JWT has expired')
		}

		// Remove JWT-specific claims and return the original payload
		const { iat, exp, ...originalPayload } =
			decoded.payload as StateTokenPayload<T>
		return originalPayload as T
	} catch (error) {
		jwtLogger.error('[ERROR] Error verifying JWT:', sanitizeError(error))

		// Re-throw with more specific error messages
		if (error instanceof Error) {
			if (error.message.includes('expired')) {
				throw new Error('JWT has expired')
			}
			if (error.message.includes('signature')) {
				throw new Error('Invalid JWT signature')
			}
		}

		throw new Error('Invalid JWT')
	}
}
