/**
 * Environment variables and bindings for the Schwab MCP worker
 *
 * This is the single source of truth for environment variable definitions.
 * In runtime, these variables are validated and accessed through AppConfig.
 */
export interface Env {
	/**
	 * Schwab OAuth client ID for API access
	 */
	SCHWAB_CLIENT_ID: string

	/**
	 * Schwab OAuth client secret for API access
	 */
	SCHWAB_CLIENT_SECRET: string

	/**
	 * Secret key used for cookie encryption
	 */
	COOKIE_ENCRYPTION_KEY: string

	/**
	 * OAuth redirect URI for callback after authentication
	 * This should be a fixed, configured value to ensure consistency
	 * across different environments and proxies
	 */
	SCHWAB_REDIRECT_URI: string

	/**
	 * KV namespace for storing tokens
	 */
	OAUTH_KV?: KVNamespace

	/**
	 * Optional log level for application logging
	 */
	LOG_LEVEL?: string
}

/**
 * A validated Env object, with all required fields validated to be non-empty
 * Used to pass around a validated set of environment variables
 * All properties are readonly to prevent accidental modification after validation
 */
export interface ValidatedEnv {
	/**
	 * Schwab OAuth client ID for API access
	 */
	readonly SCHWAB_CLIENT_ID: string

	/**
	 * Schwab OAuth client secret for API access
	 */
	readonly SCHWAB_CLIENT_SECRET: string

	/**
	 * Secret key used for cookie encryption
	 */
	readonly COOKIE_ENCRYPTION_KEY: string

	/**
	 * OAuth redirect URI for callback after authentication
	 */
	readonly SCHWAB_REDIRECT_URI: string

	/**
	 * KV namespace for storing tokens
	 */
	readonly OAUTH_KV?: KVNamespace

	/**
	 * Optional log level for application logging
	 */
	readonly LOG_LEVEL?: string
}
