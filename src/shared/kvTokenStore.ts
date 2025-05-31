import { type TokenData } from '@sudowealth/schwab-api'
import { TOKEN_KEY_PREFIX } from './constants'
import { makeLogger, LogLevel as AppLogLevel } from './logger'

/**
 * Token identifiers for KV key generation
 */
export interface TokenIdentifiers {
	schwabUserId?: string
	clientId?: string
}

/**
 * KV Token Store for centralized token persistence
 *
 * Single source of truth for OAuth tokens, eliminating dual storage
 * in DO props and KV that can lead to token divergence.
 */
interface KvTokenStore {
	load(ids: TokenIdentifiers): Promise<TokenData | null>
	save(ids: TokenIdentifiers, data: TokenData): Promise<void>
	kvKey(ids: TokenIdentifiers): string
	migrate(fromIds: TokenIdentifiers, toIds: TokenIdentifiers): Promise<boolean>
}

/**
 * Creates a KV-backed token store with consistent key schema and atomic operations
 *
 * @param kv KV namespace for token storage
 * @returns Token store interface for load/save operations
 */
export function makeKvTokenStore(kv: KVNamespace): KvTokenStore {
	const TTL_31_DAYS = 31 * 24 * 60 * 60
	// Create a scoped logger for token store operations
	const logger = makeLogger(AppLogLevel.DEBUG).withContext('token-store')

	/**
	 * Generate consistent KV key from token identifiers
	 * Priority: schwabUserId > clientId
	 */
	const kvKey = (ids: TokenIdentifiers): string => {
		const key = `${TOKEN_KEY_PREFIX}${ids.schwabUserId ?? ids.clientId}`
		if (!ids.schwabUserId && !ids.clientId) {
			throw new Error(
				'Token identifiers must include either schwabUserId or clientId',
			)
		}
		return key
	}

	/**
	 * Load token data from KV store
	 * Tries schwabUserId key first, then falls back to clientId key
	 */
	const load = async (ids: TokenIdentifiers): Promise<TokenData | null> => {
		try {
			// Try primary key first (schwabUserId preferred, or clientId if no schwabUserId)
			const primaryKey = kvKey(ids)
			let raw = await kv.get(primaryKey)
			let usedKey = primaryKey

			// If not found and we have both IDs, try the fallback key
			if (!raw && ids.schwabUserId && ids.clientId) {
				const fallbackKey = `${TOKEN_KEY_PREFIX}${ids.clientId}`
				raw = await kv.get(fallbackKey)
				if (raw) {
					usedKey = fallbackKey
					logger.debug('Token found in fallback key, will migrate', {
						primaryKey,
						fallbackKey,
					})
				}
			}

			if (!raw) {
				logger.debug('No token found in KV', {
					primaryKey,
					fallbackKey:
						ids.schwabUserId && ids.clientId
							? `${TOKEN_KEY_PREFIX}${ids.clientId}`
							: undefined,
				})
				return null
			}

			const tokenData = JSON.parse(raw) as TokenData
			logger.debug('Token loaded from KV', {
				key: usedKey,
				hasToken: !!tokenData.accessToken,
				isPrimaryKey: usedKey === primaryKey,
			})
			return tokenData
		} catch (error) {
			logger.error('Failed to load token from KV', { error, ids })
			return null
		}
	}

	/**
	 * Save token data to KV store atomically
	 * Complete TokenData is written in single operation to prevent divergence
	 */
	const save = async (
		ids: TokenIdentifiers,
		data: TokenData,
	): Promise<void> => {
		try {
			const key = kvKey(ids)
			const serialized = JSON.stringify(data)

			await kv.put(key, serialized, { expirationTtl: TTL_31_DAYS })
			logger.debug('Token saved to KV', { key, expiresAt: data.expiresAt })
		} catch (error) {
			logger.error('Failed to save token to KV', { error, ids })
			throw error
		}
	}

	/**
	 * Migrate token from one key to another
	 * Returns true if migration was successful
	 */
	const migrate = async (
		fromIds: TokenIdentifiers,
		toIds: TokenIdentifiers,
	): Promise<boolean> => {
		try {
			const fromKey = kvKey(fromIds)
			const toKey = kvKey(toIds)

			if (fromKey === toKey) {
				logger.debug('Migration not needed - keys are identical', {
					key: fromKey,
				})
				return true
			}

			const tokenData = await load(fromIds)
			if (!tokenData) {
				logger.debug('Migration not possible - no token at source key', {
					fromKey,
				})
				return false
			}

			await save(toIds, tokenData)
			logger.info('Token migrated successfully', { fromKey, toKey })

			// Don't delete the old key immediately - let it expire naturally
			// This prevents issues if there are multiple DO instances

			return true
		} catch (error) {
			logger.error('Token migration failed', { error, fromIds, toIds })
			return false
		}
	}

	return {
		load,
		save,
		kvKey,
		migrate,
	}
}
