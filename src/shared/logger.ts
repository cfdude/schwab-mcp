/**
 * Centralized logger for the application
 * Includes different log levels and ensures sensitive data is not logged
 */

export enum LogLevel {
	DEBUG = 0,
	INFO = 1,
	WARN = 2,
	ERROR = 3,
}

// Current log level for the application
// Can be set based on environment
let currentLogLevel = LogLevel.INFO

// Default keys to redact
const DEFAULT_REDACT_KEYS = [
	'password',
	'secret',
	'token',
	'key',
	'auth',
	'authorization',
	'cookie',
	'session',
]

// Custom redact keys that can be configured by consumers
let customRedactKeys: string[] = []

/**
 * Sanitizes log data to ensure no tokens or sensitive information is logged
 *
 * @param data The data to be sanitized
 * @param maxSize Optional max size for truncating large objects/arrays
 * @returns Sanitized data safe for logging
 */
function sanitizeLogData(data: any, maxSize?: number): any {
	if (typeof data === 'string') {
		// Redact potential tokens from strings
		return data
			.replace(
				/Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*/g,
				'Bearer [REDACTED]',
			)
			.replace(/Basic\s+[A-Za-z0-9+/=]+/g, 'Basic [REDACTED]')
			.replace(
				/accessToken["']?\s*:\s*["']?[^"',}]*["']?/g,
				'accessToken: "[REDACTED]"',
			)
			.replace(
				/refreshToken["']?\s*:\s*["']?[^"',}]*["']?/g,
				'refreshToken: "[REDACTED]"',
			)
	}

	if (data === null || data === undefined) {
		return data
	}

	if (typeof data === 'object') {
		if (Array.isArray(data)) {
			// Handle size limits for arrays
			if (maxSize && data.length > maxSize) {
				const preview = data
					.slice(0, maxSize)
					.map((item) => sanitizeLogData(item, maxSize))
				return {
					__preview__: true,
					items: preview,
					totalCount: data.length,
					truncated: true,
				}
			}
			return data.map((item) => sanitizeLogData(item, maxSize))
		}

		const sanitized: Record<string, any> = {}
		const allRedactKeys = [...DEFAULT_REDACT_KEYS, ...customRedactKeys]

		for (const [key, value] of Object.entries(data)) {
			// Check if key should be redacted
			if (allRedactKeys.some((k) => key.toLowerCase().includes(k))) {
				sanitized[key] = '[REDACTED]'
			} else {
				sanitized[key] = sanitizeLogData(value, maxSize)
			}
		}
		return sanitized
	}

	return data
}

/**
 * Creates a log entry with the specified level and message
 *
 * @param level The log level
 * @param message The log message
 * @param data Optional data to include with the log
 * @param contextId Optional correlation/context ID for tracing related logs
 */
function log(level: LogLevel, message: string, data?: any, contextId?: string) {
	if (level < currentLogLevel) return

	// Apply size limits to prevent Cloudflare console overflow (16KB limit)
	// For large objects, show preview only
	const maxSize = 2 // Show first 2 items for large arrays
	const sanitizedData = data ? sanitizeLogData(data, maxSize) : undefined
	const timestamp = new Date().toISOString()
	const levelName = LogLevel[level]
	const contextPrefix = contextId ? `[${contextId}] ` : ''

	switch (level) {
		case LogLevel.DEBUG:
			console.debug(
				`[${timestamp}] [${levelName}] ${contextPrefix}${message}`,
				sanitizedData,
			)
			break
		case LogLevel.INFO:
			console.info(
				`[${timestamp}] [${levelName}] ${contextPrefix}${message}`,
				sanitizedData,
			)
			break
		case LogLevel.WARN:
			console.warn(
				`[${timestamp}] [${levelName}] ${contextPrefix}${message}`,
				sanitizedData,
			)
			break
		case LogLevel.ERROR:
			console.error(
				`[${timestamp}] [${levelName}] ${contextPrefix}${message}`,
				sanitizedData,
			)
			break
	}
}

// Public API
export const logger = {
	debug: (message: string, data?: any, contextId?: string) =>
		log(LogLevel.DEBUG, message, data, contextId),
	info: (message: string, data?: any, contextId?: string) =>
		log(LogLevel.INFO, message, data, contextId),
	warn: (message: string, data?: any, contextId?: string) =>
		log(LogLevel.WARN, message, data, contextId),
	error: (message: string, data?: any, contextId?: string) =>
		log(LogLevel.ERROR, message, data, contextId),

	// Helper to create a context-aware logger that automatically includes the contextId
	withContext: (contextId: string) => ({
		debug: (message: string, data?: any) =>
			log(LogLevel.DEBUG, message, data, contextId),
		info: (message: string, data?: any) =>
			log(LogLevel.INFO, message, data, contextId),
		warn: (message: string, data?: any) =>
			log(LogLevel.WARN, message, data, contextId),
		error: (message: string, data?: any) =>
			log(LogLevel.ERROR, message, data, contextId),
	}),

	// Configuration methods
	setLevel: (level: LogLevel) => {
		currentLogLevel = level
	},

	getLevel: () => currentLogLevel,

	configureRedactKeys: (keys: string[]) => {
		customRedactKeys = keys
	},

	addRedactKeys: (keys: string[]) => {
		customRedactKeys = [...customRedactKeys, ...keys]
	},
}
