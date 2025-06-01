/**
 * Centralized redirect pattern constants
 */

export type RedirectPattern = readonly string[]

/**
 * Base redirect patterns allowed in all environments
 */
export const BASE_REDIRECT_PATTERNS = [
	// Exact matches for known MCP clients
	'^https://claude\\.ai/api/auth/callback$',
	'^https://www\\.anthropic\\.com/mcp/auth/callback$',
	// Additional trusted MCP client patterns can be added here
	// Each pattern should be a valid regular expression string
] as const satisfies RedirectPattern

/**
 * Development-only redirect patterns
 * These patterns are only allowed when NODE_ENV !== 'production'
 */
export const DEVELOPMENT_REDIRECT_PATTERNS = [
	'^http://localhost:\\d+/.*$',
	'^http://127\\.0\\.0\\.1:\\d+/.*$',
] as const satisfies RedirectPattern

/**
 * Get redirect patterns based on environment
 */
export function getRedirectPatterns(): {
	base: RedirectPattern
	dev: RedirectPattern
} {
	return {
		base: BASE_REDIRECT_PATTERNS,
		dev: DEVELOPMENT_REDIRECT_PATTERNS,
	}
}
