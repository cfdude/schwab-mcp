/**
 * Centralized redirect URI allowlist configuration
 *
 * This configuration is loaded at boot time and validated to ensure
 * all patterns are valid regular expressions. Any invalid patterns
 * will cause the application to fail fast at startup.
 */

import { BASE_REDIRECT_PATTERNS, DEVELOPMENT_REDIRECT_PATTERNS } from './redirectPatterns'

/**
 * Gets the complete list of redirect patterns based on environment
 */
export function getDefaultRedirectPatterns(): readonly string[] {
	const patterns: string[] = [...BASE_REDIRECT_PATTERNS]

	if (process.env.NODE_ENV !== 'production') {
		patterns.push(...DEVELOPMENT_REDIRECT_PATTERNS)
	}

	return patterns
}

/**
 * Validates that a pattern string is a valid regular expression
 * @throws Error if the pattern is invalid
 */
export function validateRedirectPattern(pattern: string): void {
	try {
		new RegExp(pattern)
	} catch (error) {
		throw new Error(
			`Invalid redirect URI regex pattern "${pattern}": ${error instanceof Error ? error.message : 'Unknown error'}`,
		)
	}
}

/**
 * Validates all patterns in a list
 * @throws Error if any pattern is invalid
 */
export function validateRedirectPatterns(patterns: readonly string[]): void {
	for (const pattern of patterns) {
		validateRedirectPattern(pattern)
	}
}
