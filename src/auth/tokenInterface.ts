/**
 * Common interface for token management implementations
 *
 * This interface defines the minimum required functionality that all token
 * manager implementations must provide, allowing different token managers
 * to be used interchangeably.
 */
export interface ITokenManager {
	/**
	 * Ensures a valid token is available, refreshing if necessary
	 * @returns Promise that resolves to true if token is valid, false otherwise
	 */
	ensureValidToken(): Promise<boolean>

	/**
	 * Handles reconnection scenarios
	 * @returns Promise that resolves to true if reconnection was successful
	 */
	handleReconnection(): Promise<boolean>

	/**
	 * Gets the current access token
	 * @returns Promise that resolves to the token string or null if unavailable
	 */
	getAccessToken(): Promise<string | null>

	/**
	 * Initializes the token manager and loads token state
	 * @returns Promise that resolves to true if initialization was successful
	 */
	initialize?(): Promise<boolean>

	/**
	 * Gets diagnostic information about token state
	 * @returns Promise that resolves to diagnostic information
	 */
	getDiagnostics?(): Promise<Record<string, any>>
}
