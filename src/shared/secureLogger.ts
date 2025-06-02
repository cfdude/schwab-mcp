import { sanitizeError } from '@sudowealth/schwab-api'

// Keep any MCP-specific logging logic
export function logOnlyInDevelopment(
	logger: any,
	level: string,
	message: string,
	data?: any,
): void {
	if (process.env.NODE_ENV !== 'production') {
		logger[level](message, data ? sanitizeError(data) : undefined)
	}
}
