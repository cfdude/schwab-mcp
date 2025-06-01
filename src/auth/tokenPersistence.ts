import {
	type TokenData,
	type EnhancedTokenManagerOptions,
} from '@sudowealth/schwab-api'

/**
 * Converts API TokenData to MCP TokenData format
 */
export const toApiTokenData = (mcpToken: TokenData): TokenData => ({
	// Map to @sudowealth/schwab-api's TokenSet
	accessToken: mcpToken.accessToken,
	refreshToken: mcpToken.refreshToken,
	expiresAt: mcpToken.expiresAt,
})

/**
 * Converts MCP TokenData from API TokenData format
 */
export const fromApiTokenData = (apiTokenSet: TokenData): TokenData => ({
	// Map from @sudowealth/schwab-api's TokenData/TokenSet
	accessToken: apiTokenSet.accessToken,
	refreshToken: apiTokenSet.refreshToken || '', // ensure not undefined
	expiresAt: apiTokenSet.expiresAt || 0, // ensure not undefined
})

/**
 * Maps MCP-style load/save functions to EnhancedTokenManager-compatible functions
 *
 * @param load Function to load tokens from storage
 * @param save Function to save tokens to storage
 * @returns Mapped load and save functions compatible with EnhancedTokenManager
 */
export function mapTokenPersistence(
	load?: () => Promise<TokenData | null>,
	save?: (tokenData: TokenData) => Promise<void>,
): Pick<EnhancedTokenManagerOptions, 'load' | 'save'> {
	// Create wrapper functions only if the original functions exist
	// These wrappers are created once per mapTokenPersistence call, not per request
	const mappedLoad = load
		? async () => {
				const mcpToken = await load()
				return mcpToken ? toApiTokenData(mcpToken) : null
			}
		: undefined

	const mappedSave = save
		? async (apiTokenSet: TokenData) => {
				await save(fromApiTokenData(apiTokenSet))
			}
		: undefined

	return {
		load: mappedLoad,
		save: mappedSave,
	}
}
