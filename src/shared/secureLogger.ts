const isProduction = () => process.env.NODE_ENV === 'production'

function sanitizeForLog(obj: any): any {
	if (obj === null || obj === undefined) {
		return obj
	}

	if (typeof obj === 'string') {
		if (obj.startsWith('token:')) {
			return `token:${obj.slice(6, 10)}***`
		}
		if (obj.includes('schwab') || obj.includes('client') || obj.length > 20) {
			return `${obj.substring(0, 8)}***`
		}
		return obj
	}

	if (Array.isArray(obj)) {
		return obj.map(sanitizeForLog)
	}

	if (typeof obj === 'object') {
		const sanitized: any = {}
		for (const [key, value] of Object.entries(obj)) {
			if (shouldRedactKey(key)) {
				sanitized[key] = '***'
			} else {
				sanitized[key] = sanitizeForLog(value)
			}
		}
		return sanitized
	}

	return obj
}

function shouldRedactKey(key: string): boolean {
	const sensitiveKeys = [
		'schwabUserId',
		'clientId',
		'accountNumber',
		'hashValue',
		'schwabClientCorrelId',
		'sourceKey',
		'expectedKey',
		'tokenKey',
		'key',
		'authorization',
		'cookie',
		'token',
		'secret',
		'password',
		'code_verifier',
		'code_challenge',
		'refresh_token',
		'access_token',
		'id_token',
		'auth_token',
		'bearer',
		'api_key',
		'private_key',
		'certificate',
		'signature',
		'hash',
		'credentials',
		'auth',
	]

	const lowerKey = key.toLowerCase()
	return sensitiveKeys.some((sensitive) => lowerKey.includes(sensitive))
}

export function sanitizeKeyForLog(key: string): string {
	if (!key) return key
	if (key.length <= 10) return key
	return `${key.substring(0, 8)}***`
}

export function logOnlyInDevelopment(
	logger: any,
	level: string,
	message: string,
	data?: any,
) {
	if (!isProduction()) {
		logger[level](message, data ? sanitizeForLog(data) : undefined)
	}
}

/**
 * Sanitizes error objects for safe logging
 * Removes sensitive data while preserving useful debugging information
 */
export function sanitizeError(error: unknown): Record<string, any> {
	if (!error || typeof error !== 'object') {
		return { message: String(error) }
	}

	const err = error as any
	const sanitized: Record<string, any> = {}

	// Safe properties to include
	const safeProps = ['name', 'code', 'statusCode', 'status', 'type']
	for (const prop of safeProps) {
		if (prop in err) {
			sanitized[prop] = err[prop]
		}
	}

	// Sanitize message - remove potential sensitive data patterns
	if ('message' in err) {
		sanitized.message = sanitizeForLog(String(err.message))
	}

	// Handle stack traces - only include in development
	if ('stack' in err && !isProduction()) {
		// Remove file paths that might reveal system structure
		sanitized.stack = String(err.stack)
			.split('\n')
			.slice(0, 5) // Limit stack trace depth
			.join('\n')
	}

	return sanitized
}
