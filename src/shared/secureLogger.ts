const isProduction = () => process.env.NODE_ENV === 'production'

export function sanitizeForLog(obj: any): any {
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
		'jwt',
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

export function createSecureLogger(logger: any) {
	return {
		debug: (message: string, data?: any) => {
			if (isProduction() && data && containsSensitiveData(data)) {
				logger.debug(message, sanitizeForLog(data))
			} else {
				logger.debug(message, data)
			}
		},
		info: (message: string, data?: any) => {
			logger.info(message, data ? sanitizeForLog(data) : undefined)
		},
		warn: (message: string, data?: any) => {
			logger.warn(message, data ? sanitizeForLog(data) : undefined)
		},
		error: (message: string, data?: any) => {
			logger.error(message, data ? sanitizeForLog(data) : undefined)
		},
	}
}

function containsSensitiveData(data: any): boolean {
	if (!data || typeof data !== 'object') return false

	const dataStr = JSON.stringify(data).toLowerCase()
	const sensitivePatterns = [
		'schwab',
		'client',
		'token',
		'key',
		'secret',
		'password',
		'authorization',
		'cookie',
		'account',
		'hash',
	]

	return sensitivePatterns.some((pattern) => dataStr.includes(pattern))
}
