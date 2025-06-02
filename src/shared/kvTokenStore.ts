import { type TokenData } from '@sudowealth/schwab-api'
import pino from 'pino'
import { TOKEN_KEY_PREFIX, TTL_31_DAYS } from './constants'
import { sanitizeKeyForLog } from './secureLogger'

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
export interface KvTokenStore<T extends TokenData = TokenData> {
	load(ids: TokenIdentifiers): Promise<T | null>
	save(ids: TokenIdentifiers, data: T): Promise<void>
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
export function makeKvTokenStore<T extends TokenData = TokenData>(
	kv: KVNamespace,
): KvTokenStore<T> {
	// Create a Pino child logger for token store operations
	const kvLogger = pino().child({ contextId: 'kv-token-store' })

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
	 * Reads both schwabUserId and clientId keys in parallel, with schwabUserId taking precedence
	 */
	const load = async (ids: TokenIdentifiers): Promise<T | null> => {
		try {
			// Build list of keys to check
			const keysToCheck: string[] = []
			const schwabUserKey = ids.schwabUserId
				? `${TOKEN_KEY_PREFIX}${ids.schwabUserId}`
				: null
			const clientKey = ids.clientId
				? `${TOKEN_KEY_PREFIX}${ids.clientId}`
				: null

			if (schwabUserKey) keysToCheck.push(schwabUserKey)
			if (clientKey && clientKey !== schwabUserKey) keysToCheck.push(clientKey)

			if (keysToCheck.length === 0) {
				throw new Error(
					'Token identifiers must include either schwabUserId or clientId',
				)
			}

			// Read all keys in parallel
			const results = await Promise.all(
				keysToCheck.map((key) => kv.get(key).then((value) => ({ key, value }))),
			)

			// Find the first non-null result, prioritizing schwabUserId
			let tokenData: T | null = null
			let sourceKey: string | null = null

			for (const { key, value } of results) {
				if (value) {
					tokenData = JSON.parse(value) as T
					sourceKey = key
					break
				}
			}

			kvLogger.debug(
				{
					keysCheckedCount: keysToCheck.length,
					sourceKeyPrefix: sourceKey ? sanitizeKeyForLog(sourceKey) : 'none',
				},
				'Token lookup completed',
			)

			// If we found a token under clientId but have a schwabUserId, migrate it
			if (
				tokenData &&
				sourceKey === clientKey &&
				schwabUserKey &&
				clientKey &&
				schwabUserKey !== sourceKey
			) {
				kvLogger.info(
					{
						fromKeyPrefix: sanitizeKeyForLog(clientKey),
						toKeyPrefix: sanitizeKeyForLog(schwabUserKey),
					},
					'Migrating token from clientId to schwabUserId key',
				)

				// Atomically migrate: put to new key, then delete old key
				await kv.put(schwabUserKey, JSON.stringify(tokenData), {
					expirationTtl: TTL_31_DAYS,
				})
				await kv.delete(clientKey)

				kvLogger.debug(
					{
						fromKeyPrefix: sanitizeKeyForLog(clientKey),
						toKeyPrefix: sanitizeKeyForLog(schwabUserKey),
					},
					'Token migration completed',
				)
			}

			return tokenData
		} catch (error) {
			kvLogger.error({ error }, 'Failed to load token from KV')
			return null
		}
	}

	/**
	 * Save token data to KV store atomically
	 * Complete TokenData is written in single operation to prevent divergence
	 */
	const save = async (ids: TokenIdentifiers, data: T): Promise<void> => {
		try {
			const key = kvKey(ids)
			const serialized = JSON.stringify(data)

			await kv.put(key, serialized, { expirationTtl: TTL_31_DAYS })
			kvLogger.debug({ keyPrefix: sanitizeKeyForLog(key) }, 'Token saved to KV')
		} catch (error) {
			kvLogger.error({ error }, 'Failed to save token to KV')
			throw error
		}
	}

	/**
	 * Migrate token from one key to another
	 * Returns true if migration was successful
	 * Implements idempotent migration to prevent race conditions between multiple DO instances
	 */
	const migrate = async (
		fromIds: TokenIdentifiers,
		toIds: TokenIdentifiers,
	): Promise<boolean> => {
		try {
			const fromKey = kvKey(fromIds)
			const toKey = kvKey(toIds)

			if (fromKey === toKey) {
				kvLogger.debug(
					{
						keyPrefix: sanitizeKeyForLog(fromKey),
					},
					'Migration not needed - keys are identical',
				)
				return true
			}

			// First check if destination already exists to avoid race conditions
			const existingAtDestination = await kv.get(toKey)
			if (existingAtDestination) {
				kvLogger.debug(
					{ toKeyPrefix: sanitizeKeyForLog(toKey) },
					'Migration skipped - token already exists at destination',
				)
				// If token exists at destination, clean up source silently
				try {
					await kv.delete(fromKey)
				} catch (deleteError) {
					kvLogger.debug(
						{
							fromKeyPrefix: sanitizeKeyForLog(fromKey),
							error: deleteError,
						},
						'Source cleanup after existing destination failed',
					)
				}
				return false
			}

			// Read the token directly from the source key
			const raw = await kv.get(fromKey)
			if (!raw) {
				kvLogger.debug(
					{ fromKeyPrefix: sanitizeKeyForLog(fromKey) },
					'Migration source token not found',
				)
				return false
			}

			// Parse token data for migration
			JSON.parse(raw) as T
			kvLogger.debug(
				{
					fromKeyPrefix: sanitizeKeyForLog(fromKey),
				},
				'Migration source token found',
			)

			// Atomically migrate: put to new key first
			await kv.put(toKey, raw, { expirationTtl: TTL_31_DAYS })

			// Then delete old key - if this fails due to race condition, log but continue
			try {
				await kv.delete(fromKey)
			} catch (deleteError) {
				kvLogger.debug(
					{
						fromKeyPrefix: sanitizeKeyForLog(fromKey),
						error: deleteError,
					},
					'Source key deletion may have raced with another instance',
				)
			}

			kvLogger.info(
				{
					fromKeyPrefix: sanitizeKeyForLog(fromKey),
					toKeyPrefix: sanitizeKeyForLog(toKey),
				},
				'Token migrated successfully',
			)
			return true
		} catch (error) {
			kvLogger.error({ error }, 'Token migration failed')
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
			kvLogger.debug(
				{
					success: migrateSuccess,
					fromKeyPrefix: sanitizeKeyForLog(kvKey(fromIds)),
					toKeyPrefix: sanitizeKeyForLog(kvKey(toIds)),
				},
				'Migration attempt completed',
			)
		} catch (migrationError) {
			kvLogger.warn(
				{
					error:
						migrationError instanceof Error
							? migrationError.message
							: String(migrationError),
				},
				'Token migration failed during migrateIfNeeded',
			)
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
