/**
 * Centralized logger for the application
 * Includes different log levels and ensures sensitive data is not logged
 */

export enum LogLevel {
	Debug = 0,
	Info = 1,
	Warn = 2,
	Error = 3,
}

// Configurable regex patterns for masking secrets
interface SecretPattern {
	pattern: RegExp
	replacement: string
}

// Default patterns for common secrets
const DEFAULT_SECRET_PATTERNS: SecretPattern[] = [
	// Bearer tokens
	{
		pattern:
			/Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_\.\+\/=]*/g,
		replacement: 'Bearer [REDACTED]',
	},
	// Basic auth
	{
		pattern: /Basic\s+[A-Za-z0-9+/=]+/g,
		replacement: 'Basic [REDACTED]',
	},
	// Access tokens in JSON-like strings
	{
		pattern: /accessToken["']?\s*:\s*["']?[A-Za-z0-9\-_\.\+\/=]+["']?/g,
		replacement: 'accessToken: "[REDACTED]"',
	},
	// Refresh tokens in JSON-like strings
	{
		pattern: /refreshToken["']?\s*:\s*["']?[A-Za-z0-9\-_\.\+\/=]+["']?/g,
		replacement: 'refreshToken: "[REDACTED]"',
	},
	// API keys
	{
		pattern: /api[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9\-_]{20,}["']?/gi,
		replacement: 'api_key: "[REDACTED]"',
	},
	// Passwords in URLs
	{
		pattern: /:\/\/[^:]+:([^@]+)@/g,
		replacement: '://[USER]:[REDACTED]@',
	},
]

// Default keys to redact in objects
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

// Logger state interface to encapsulate mutable configuration
interface LoggerState {
	currentLogLevel: LogLevel
	customSecretPatterns: SecretPattern[]
	customRedactKeys: string[]
}

// Child logger interface (without configuration methods)
interface ChildLogger {
	debug: (message: string, data?: any) => void
	info: (message: string, data?: any) => void
	warn: (message: string, data?: any) => void
	error: (message: string, data?: any) => void
}

// Logger interface
interface Logger {
	debug: (message: string, data?: any, contextId?: string) => void
	info: (message: string, data?: any, contextId?: string) => void
	warn: (message: string, data?: any, contextId?: string) => void
	error: (message: string, data?: any, contextId?: string) => void
	child: (contextId: string) => ChildLogger
}

// Get log level from environment or default to Info
function getLevelFromEnv(): LogLevel {
	const envLevel = process.env.LOG_LEVEL?.toUpperCase()
	if (envLevel && envLevel in LogLevel) {
		return LogLevel[envLevel as keyof typeof LogLevel] as LogLevel
	}
	return LogLevel.Info
}

// Singleton root state - mutable for configuration
const rootState: LoggerState = {
	currentLogLevel: getLevelFromEnv(),
	customSecretPatterns: [],
	customRedactKeys: [],
}

/**
 * Builds the logger functionality with the given state
 */
function buildLogger(state: LoggerState): Logger {
	/**
	 * Sanitizes log data to ensure no tokens or sensitive information is logged
	 *
	 * @param data The data to be sanitized
	 * @param maxSize Optional max size for truncating large objects/arrays
	 * @returns Sanitized data safe for logging
	 */
	function sanitizeLogData(data: any, maxSize?: number): any {
		if (typeof data === 'string') {
			// Apply all secret patterns in a single pass
			const allPatterns = [
				...DEFAULT_SECRET_PATTERNS,
				...state.customSecretPatterns,
			]
			let sanitizedString = data

			for (const { pattern, replacement } of allPatterns) {
				sanitizedString = sanitizedString.replace(pattern, replacement)
			}

			return sanitizedString
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
			const allRedactKeys = [...DEFAULT_REDACT_KEYS, ...state.customRedactKeys]

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
	function log(
		level: LogLevel,
		message: string,
		data?: any,
		contextId?: string,
	) {
		if (level < state.currentLogLevel) return

		// Apply size limits to prevent Cloudflare console overflow (16KB limit)
		// For large objects, show preview only
		const maxSize = 2 // Show first 2 items for large arrays
		const sanitizedData = data ? sanitizeLogData(data, maxSize) : undefined
		const timestamp = new Date().toISOString()
		const levelName = LogLevel[level]
		const contextPrefix = contextId ? `[${contextId}] ` : ''

		switch (level) {
			case LogLevel.Debug:
				console.debug(
					`[${timestamp}] [${levelName}] ${contextPrefix}${message}`,
					sanitizedData,
				)
				break
			case LogLevel.Info:
				console.info(
					`[${timestamp}] [${levelName}] ${contextPrefix}${message}`,
					sanitizedData,
				)
				break
			case LogLevel.Warn:
				console.warn(
					`[${timestamp}] [${levelName}] ${contextPrefix}${message}`,
					sanitizedData,
				)
				break
			case LogLevel.Error:
				console.error(
					`[${timestamp}] [${levelName}] ${contextPrefix}${message}`,
					sanitizedData,
				)
				break
		}
	}

	// Return the logger instance
	return {
		debug: (message: string, data?: any, contextId?: string) =>
			log(LogLevel.Debug, message, data, contextId),
		info: (message: string, data?: any, contextId?: string) =>
			log(LogLevel.Info, message, data, contextId),
		warn: (message: string, data?: any, contextId?: string) =>
			log(LogLevel.Warn, message, data, contextId),
		error: (message: string, data?: any, contextId?: string) =>
			log(LogLevel.Error, message, data, contextId),

		// Create a child logger with a fixed context
		child: (contextId: string): ChildLogger => ({
			debug: (message: string, data?: any) =>
				log(LogLevel.Debug, message, data, contextId),
			info: (message: string, data?: any) =>
				log(LogLevel.Info, message, data, contextId),
			warn: (message: string, data?: any) =>
				log(LogLevel.Warn, message, data, contextId),
			error: (message: string, data?: any) =>
				log(LogLevel.Error, message, data, contextId),
		}),
	}
}

// Create singleton logger instance
export const logger = buildLogger(rootState)

// Export the AppLogger type
export type AppLogger = typeof logger

/**
 * Configure the global logger level
 * @param level The new log level to set
 */
export function configureLogger(level: LogLevel) {
	rootState.currentLogLevel = level
}
