/**
 * Centralized redirect URI allowlist configuration
 *
 * This configuration is loaded at boot time and validated to ensure
 * all patterns are valid regular expressions. Any invalid patterns
 * will cause the application to fail fast at startup.
 */

/**
 * Default redirect URI patterns for trusted MCP clients
 * These patterns are always included and cannot be modified at runtime
 */
const DEFAULT_REDIRECT_PATTERNS = [
	// Exact matches for known MCP clients
	'^https://claude\\.ai/api/auth/callback$',
	'^https://www\\.anthropic\\.com/mcp/auth/callback$',

	// Additional trusted MCP client patterns can be added here
	// Each pattern should be a valid regular expression string
] as const

/**
 * Development-only redirect patterns
 * These are only included when NODE_ENV !== 'production'
 */
const DEVELOPMENT_REDIRECT_PATTERNS = [
	'^http://localhost:\\d+/.*$',
	'^http://127\\.0\\.0\\.1:\\d+/.*$',
] as const

/**
 * Gets the complete list of redirect patterns based on environment
 */
export function getDefaultRedirectPatterns(): readonly string[] {
	const patterns: string[] = [...DEFAULT_REDIRECT_PATTERNS]

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
