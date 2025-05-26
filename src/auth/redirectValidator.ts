import { logger } from '../shared/logger'

/**
 * Validates redirect URIs against an allowlist of trusted patterns
 */
class RedirectValidator {
	private readonly allowedPatterns: RegExp[]

	constructor(patterns: string[]) {
		this.allowedPatterns = patterns.map((pattern) => {
			try {
				return new RegExp(pattern)
			} catch (error) {
				logger.error(`Invalid redirect URI pattern: ${pattern}`, error)
				throw new Error(`Invalid redirect URI pattern: ${pattern}`)
			}
		})
	}

	/**
	 * Validates a single redirect URI against the allowlist
	 */
	isValidRedirectUri(uri: string): boolean {
		if (!uri) {
			return false
		}

		try {
			const url = new URL(uri)

			// Basic security checks
			if (url.protocol !== 'https:' && url.protocol !== 'http:') {
				logger.warn(`Invalid protocol in redirect URI: ${uri}`)
				return false
			}

			// Don't allow localhost in production
			if (
				process.env.NODE_ENV === 'production' &&
				(url.hostname === 'localhost' || url.hostname === '127.0.0.1')
			) {
				logger.warn(`Localhost redirect URI not allowed in production: ${uri}`)
				return false
			}

			// Check against allowlist patterns
			const isAllowed = this.allowedPatterns.some((pattern) =>
				pattern.test(uri),
			)

			if (!isAllowed) {
				logger.warn(`Redirect URI not in allowlist: ${uri}`)
			}

			return isAllowed
		} catch (error) {
			logger.warn(`Invalid redirect URI format: ${uri}`, error)
			return false
		}
	}

	/**
	 * Filters a list of redirect URIs to only include valid ones
	 */
	filterValidRedirectUris(uris: string[]): string[] {
		return uris.filter((uri) => this.isValidRedirectUri(uri))
	}
}

// Default allowlist patterns for common MCP client redirect URIs
const DEFAULT_REDIRECT_PATTERNS = [
	// Exact matches for known MCP clients
	'^https://claude\\.ai/api/auth/callback$',
	'^https://www\\.anthropic\\.com/mcp/auth/callback$',

	// Pattern for localhost development (only in non-production)
	...(process.env.NODE_ENV !== 'production'
		? ['^http://localhost:\\d+/.*$', '^http://127\\.0\\.0\\.1:\\d+/.*$']
		: []),

	// Add more patterns as needed for trusted MCP clients
]

// Create a default validator instance
export const defaultRedirectValidator = new RedirectValidator(
	DEFAULT_REDIRECT_PATTERNS,
)
