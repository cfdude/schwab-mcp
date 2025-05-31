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

// Logger options for configuration
interface LoggerOpts {
	secretPatterns?: SecretPattern[]
	redactKeys?: string[]
}

// Logger interface
interface Logger {
	debug: (message: string, data?: any, contextId?: string) => void
	info: (message: string, data?: any, contextId?: string) => void
	warn: (message: string, data?: any, contextId?: string) => void
	error: (message: string, data?: any, contextId?: string) => void
	withContext: (
		contextId: string,
	) => Omit<
		Logger,
		| 'withContext'
		| 'setLevel'
		| 'getLevel'
		| 'configureRedactKeys'
		| 'addRedactKeys'
		| 'configureSecretPatterns'
		| 'addSecretPatterns'
		| 'addSecretPattern'
		| 'child'
	>
	setLevel: (level: LogLevel) => void
	getLevel: () => LogLevel
	configureRedactKeys: (keys: string[]) => void
	addRedactKeys: (keys: string[]) => void
	configureSecretPatterns: (patterns: SecretPattern[]) => void
	addSecretPatterns: (patterns: SecretPattern[]) => void
	addSecretPattern: (pattern: RegExp, replacement: string) => void
	child: (opts?: Partial<LoggerOpts>) => Logger
}

/**
 * Creates a logger instance with isolated state
 *
 * @param level The log level for this logger instance
 * @param opts Optional configuration for secret patterns and redact keys
 * @returns A logger instance with isolated configuration
 */
export function makeLogger(
	level: LogLevel,
	opts?: Partial<LoggerOpts>,
): Logger {
	// Create isolated state for this logger instance
	const state: LoggerState = {
		currentLogLevel: level,
		customSecretPatterns: opts?.secretPatterns || [],
		customRedactKeys: opts?.redactKeys || [],
	}

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

	// Return the logger instance with isolated state
	return {
		debug: (message: string, data?: any, contextId?: string) =>
			log(LogLevel.Debug, message, data, contextId),
		info: (message: string, data?: any, contextId?: string) =>
			log(LogLevel.Info, message, data, contextId),
		warn: (message: string, data?: any, contextId?: string) =>
			log(LogLevel.Warn, message, data, contextId),
		error: (message: string, data?: any, contextId?: string) =>
			log(LogLevel.Error, message, data, contextId),

		// Helper to create a context-aware logger that automatically includes the contextId
		withContext: (contextId: string) => ({
			debug: (message: string, data?: any) =>
				log(LogLevel.Debug, message, data, contextId),
			info: (message: string, data?: any) =>
				log(LogLevel.Info, message, data, contextId),
			warn: (message: string, data?: any) =>
				log(LogLevel.Warn, message, data, contextId),
			error: (message: string, data?: any) =>
				log(LogLevel.Error, message, data, contextId),
		}),

		// Configuration methods
		setLevel: (level: LogLevel) => {
			state.currentLogLevel = level
		},

		getLevel: () => state.currentLogLevel,

		configureRedactKeys: (keys: string[]) => {
			state.customRedactKeys = keys
		},

		addRedactKeys: (keys: string[]) => {
			state.customRedactKeys = [...state.customRedactKeys, ...keys]
		},

		configureSecretPatterns: (patterns: SecretPattern[]) => {
			state.customSecretPatterns = patterns
		},

		addSecretPatterns: (patterns: SecretPattern[]) => {
			state.customSecretPatterns = [...state.customSecretPatterns, ...patterns]
		},

		addSecretPattern: (pattern: RegExp, replacement: string) => {
			state.customSecretPatterns = [
				...state.customSecretPatterns,
				{ pattern, replacement },
			]
		},

		// Create a child logger that inherits current configuration
		child: (opts?: Partial<LoggerOpts>) => {
			return makeLogger(state.currentLogLevel, {
				secretPatterns: [
					...state.customSecretPatterns,
					...(opts?.secretPatterns || []),
				],
				redactKeys: [...state.customRedactKeys, ...(opts?.redactKeys || [])],
			})
		},
	}
}

// Get log level from environment or default to Info
function getLogLevelFromEnv(): LogLevel {
	const envLevel = process.env.LOG_LEVEL?.toUpperCase()
	if (envLevel && envLevel in LogLevel) {
		return LogLevel[envLevel as keyof typeof LogLevel] as LogLevel
	}
	return LogLevel.Info
}

// Create singleton root logger instance
const rootLogger = makeLogger(getLogLevelFromEnv())

// Re-export the singleton logger instance
export const logger = rootLogger
