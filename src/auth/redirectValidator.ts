import { type ValidatedEnv } from '../../types/env'
import {
	getDefaultRedirectPatterns,
	validateRedirectPattern,
	validateRedirectPatterns,
} from '../config'
import { logger } from '../shared/log'

/**
 * Validates redirect URIs against an allowlist of trusted patterns
 */
class RedirectValidator {
	private readonly allowedPatterns: RegExp[]
	private readonly config: ValidatedEnv

	constructor(patterns: string[], config: ValidatedEnv) {
		// Validate all patterns before creating RegExp instances
		// This ensures fail-fast behavior at initialization
		validateRedirectPatterns(patterns)

		this.allowedPatterns = patterns.map((pattern) => new RegExp(pattern))
		this.config = config
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
				logger.warn('Invalid protocol in redirect URI')
				return false
			}

			// Don't allow localhost in production
			const isProduction = this.config.ENVIRONMENT === 'production'
			if (
				isProduction &&
				(url.hostname === 'localhost' || url.hostname === '127.0.0.1')
			) {
				logger.warn('Localhost redirect URI not allowed in production')
				return false
			}

			// Check against allowlist patterns
			const isAllowed = this.allowedPatterns.some((pattern) =>
				pattern.test(uri),
			)

			if (!isAllowed) {
				logger.warn('Redirect URI not in allowlist')
			}

			return isAllowed
		} catch (error) {
			logger.warn('Invalid redirect URI format', error)
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

/**
 * Creates a redirect validator with configurable patterns from environment
 * @throws Error if any pattern (default or from environment) is invalid
 */
export function createRedirectValidator(
	config: ValidatedEnv,
): RedirectValidator {
	const patterns = [...getDefaultRedirectPatterns()]

	if (config.ALLOWED_REDIRECT_REGEXPS) {
		const additionalPatterns = config.ALLOWED_REDIRECT_REGEXPS.split(',')
			.map((pattern) => pattern.trim())
			.filter((pattern) => pattern.length > 0)

		// Validate each additional pattern before adding
		for (const pattern of additionalPatterns) {
			try {
				validateRedirectPattern(pattern)
			} catch (error) {
				// Log the error and throw to fail fast
				logger.error(
					`Invalid redirect URI pattern from ALLOWED_REDIRECT_REGEXPS: ${pattern}`,
					error,
				)
				throw error
			}
		}

		patterns.push(...additionalPatterns)
	}

	return new RedirectValidator(patterns, config)
}
