import { type TokenData } from '@sudowealth/schwab-api'
import { TOKEN_KEY_PREFIX, TTL_31_DAYS, LOGGER_CONTEXTS } from './constants'
import { logger } from './log'

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
	migrateIfNeeded(
		fromIds: TokenIdentifiers,
		toIds: TokenIdentifiers,
	): Promise<void>
}

/**
 * Creates a KV-backed token store with consistent key schema and atomic operations
 *
 * @param kv KV namespace for token storage
 * @returns Token store interface for load/save operations
 */
export function makeKvTokenStore(kv: KVNamespace): KvTokenStore {
	// Create a scoped logger for token store operations
	const kvLogger = logger.child(LOGGER_CONTEXTS.KV_TOKEN_STORE)

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
				}
				kvLogger.debug('Fallback key lookup completed', {
					primaryKey,
					fallbackKey,
					foundInFallback: !!raw,
				})
			}

			kvLogger.debug('Token lookup result', {
				primaryKey,
				fallbackKey:
					ids.schwabUserId && ids.clientId
						? `${TOKEN_KEY_PREFIX}${ids.clientId}`
						: undefined,
				found: !!raw,
				usedKey: raw ? usedKey : 'none',
			})
			if (!raw) {
				return null
			}

			const tokenData = JSON.parse(raw) as TokenData
			kvLogger.debug('Token loaded from KV', {
				key: usedKey,
				hasToken: !!tokenData.accessToken,
				isPrimaryKey: usedKey === primaryKey,
			})
			return tokenData
		} catch (error) {
			kvLogger.error('Failed to load token from KV', { error, ids })
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
			kvLogger.debug('Token saved to KV', { key, expiresAt: data.expiresAt })
		} catch (error) {
			kvLogger.error('Failed to save token to KV', { error, ids })
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
				kvLogger.debug('Migration not needed - keys are identical', {
					key: fromKey,
				})
				return true
			}

			const tokenData = await load(fromIds)
			kvLogger.debug('Migration source token lookup', {
				fromKey,
				tokenFound: !!tokenData,
			})
			if (!tokenData) {
				return false
			}

			await save(toIds, tokenData)
			kvLogger.info('Token migrated successfully', { fromKey, toKey })

			// Don't delete the old key immediately - let it expire naturally
			// This prevents issues if there are multiple DO instances

			return true
		} catch (error) {
			kvLogger.error('Token migration failed', { error, fromIds, toIds })
			return false
		}
	}

	/**
	 * Check if migration is needed and perform it if required
	 * Encapsulates the migration logic that was previously in MyMCP.init()
	 */
	const migrateIfNeeded = async (
		fromIds: TokenIdentifiers,
		toIds: TokenIdentifiers,
	): Promise<void> => {
		try {
			const migrateSuccess = await migrate(fromIds, toIds)
			kvLogger.debug('Migration attempt completed', {
				success: migrateSuccess,
				fromKey: kvKey(fromIds),
				toKey: kvKey(toIds),
			})
		} catch (migrationError) {
			kvLogger.warn('Token migration failed during migrateIfNeeded', {
				error:
					migrationError instanceof Error
						? migrationError.message
						: String(migrationError),
				fromIds,
				toIds,
			})
		}
	}

	return {
		load,
		save,
		kvKey,
		migrate,
		migrateIfNeeded,
	}
}
