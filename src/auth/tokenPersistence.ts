import {
	type TokenData,
	type EnhancedTokenManagerOptions,
} from '@sudowealth/schwab-api'

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
	const mappedLoad = load
		? async () => {
				const mcpToken = await load()
				if (!mcpToken) return null
				return {
					// Map to @sudowealth/schwab-api's TokenSet
					accessToken: mcpToken.accessToken,
					refreshToken: mcpToken.refreshToken,
					expiresAt: mcpToken.expiresAt,
				}
			}
		: undefined

	const mappedSave = save
		? async (apiTokenSet: TokenData) => {
				await save({
					// Map from @sudowealth/schwab-api's TokenData/TokenSet
					accessToken: apiTokenSet.accessToken,
					refreshToken: apiTokenSet.refreshToken || '', // ensure not undefined
					expiresAt: apiTokenSet.expiresAt || 0, // ensure not undefined
				})
			}
		: undefined

	return {
		load: mappedLoad,
		save: mappedSave,
	}
}