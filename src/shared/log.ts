/**
 * Lightweight Pino logger wrapper for Cloudflare Workers
 * Provides structured logging with automatic secret redaction
 */

import pino from 'pino'

// Pino log levels
export type PinoLogLevel =
	| 'trace'
	| 'debug'
	| 'info'
	| 'warn'
	| 'error'
	| 'fatal'

// Logger type that matches our existing interface
export interface AppLogger {
	debug: (message: string, data?: any, contextId?: string) => void
	info: (message: string, data?: any, contextId?: string) => void
	warn: (message: string, data?: any, contextId?: string) => void
	error: (message: string, data?: any, contextId?: string) => void
	child: (contextId: string) => ChildLogger
}

// Child logger interface
export interface ChildLogger {
	debug: (message: string, data?: any) => void
	info: (message: string, data?: any) => void
	warn: (message: string, data?: any) => void
	error: (message: string, data?: any) => void
}

// Redaction paths for sensitive data
const REDACT_PATHS = [
	'password',
	'secret',
	'token',
	'key',
	'auth',
	'authorization',
	'cookie',
	'session',
	'accessToken',
	'refreshToken',
	'api_key',
	'apiKey',
	'client_secret',
	'clientSecret',
	'*.password',
	'*.secret',
	'*.token',
	'*.key',
	'*.auth',
	'*.authorization',
	'*.cookie',
	'*.session',
	'*.accessToken',
	'*.refreshToken',
	'*.api_key',
	'*.apiKey',
	'*.client_secret',
	'*.clientSecret',
]

// Custom serializers for additional redaction
const serializers = {
	// Redact authorization headers
	req: (req: any) => {
		const serialized = pino.stdSerializers.req(req)
		if (serialized.headers?.authorization) {
			serialized.headers.authorization = '[REDACTED]'
		}
		if (serialized.headers?.cookie) {
			serialized.headers.cookie = '[REDACTED]'
		}
		return serialized
	},
	// Redact sensitive error properties
	err: (err: any) => {
		const serialized = pino.stdSerializers.err(err)
		// Add any custom error redaction here if needed
		return serialized
	},
}

// Pino configuration for Cloudflare Workers
const pinoConfig: pino.LoggerOptions = {
	// Use browser transport for console output in Workers
	browser: {
		asObject: false,
		serialize: true,
	},
	// Set redaction paths
	redact: {
		paths: REDACT_PATHS,
		censor: '[REDACTED]',
	},
	// Custom serializers
	serializers,
	// Format timestamps
	timestamp: pino.stdTimeFunctions.isoTime,
	// Base context
	base: {
		env: 'cloudflare-worker',
	},
}

/**
 * Build a logger instance with the specified log level
 */
export function buildLogger(level: PinoLogLevel = 'info'): AppLogger {
	// Create base pino instance
	const baseLogger = pino({
		...pinoConfig,
		level,
	})

	// Create wrapper that matches our existing interface
	const createLogFunction = (
		logFn: pino.LogFn,
	): ((message: string, data?: any, contextId?: string) => void) => {
		return (message: string, data?: any, contextId?: string) => {
			if (contextId) {
				logFn({ contextId, ...data }, message)
			} else if (data !== undefined) {
				logFn(data, message)
			} else {
				logFn(message)
			}
		}
	}

	const logger: AppLogger = {
		debug: createLogFunction(baseLogger.debug.bind(baseLogger)),
		info: createLogFunction(baseLogger.info.bind(baseLogger)),
		warn: createLogFunction(baseLogger.warn.bind(baseLogger)),
		error: createLogFunction(baseLogger.error.bind(baseLogger)),
		child: (contextId: string): ChildLogger => {
			const childLogger = baseLogger.child({ contextId })
			return {
				debug: (message: string, data?: any) =>
					data !== undefined
						? childLogger.debug(data, message)
						: childLogger.debug(message),
				info: (message: string, data?: any) =>
					data !== undefined
						? childLogger.info(data, message)
						: childLogger.info(message),
				warn: (message: string, data?: any) =>
					data !== undefined
						? childLogger.warn(data, message)
						: childLogger.warn(message),
				error: (message: string, data?: any) =>
					data !== undefined
						? childLogger.error(data, message)
						: childLogger.error(message),
			}
		},
	}

	return logger
}

// Create singleton logger instance with default level
// This will be reconfigured in MyMCP.init() with the actual level from config
export const logger = buildLogger('info')

// Export type for compatibility
export type { AppLogger as AppLoggerType }
