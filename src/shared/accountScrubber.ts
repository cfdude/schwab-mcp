import { type SchwabApiClient } from '@sudowealth/schwab-api'
import { logger } from './log'

type AccountDisplayMap = Record<string, string>

type UnknownScrubbed<T> =
	T extends Array<infer U>
		? UnknownScrubbed<U>[]
		: T extends object
			? {
					[K in keyof T as K extends 'accountNumber' | 'hashValue'
						? never
						: K]: UnknownScrubbed<T[K]>
				} & {
					accountDisplay?: string
				}
			: T

/**
 * Build a mapping of account identifiers to a human friendly display string.
 * The mapping includes both raw account numbers and hashed account numbers.
 */
export async function buildAccountDisplayMap(
	client: SchwabApiClient,
): Promise<AccountDisplayMap> {
	const [userPref, accountNumbers] = await Promise.all([
		client.trader.userPreference.getUserPreference(),
		client.trader.accounts.getAccountNumbers(),
	])

	const prefMap = new Map<string, string>()
	for (const acc of userPref.accounts) {
		prefMap.set(acc.accountNumber, `${acc.nickName} ${acc.displayAcctId} `)
	}

	const map: AccountDisplayMap = {}
	for (const acc of accountNumbers) {
		const display =
			prefMap.get(acc.accountNumber) ?? `Account ${acc.accountNumber}`
		map[acc.accountNumber] = display
		map[acc.hashValue] = display
	}
	logger.debug('[AccountScrubber] Built account display map', {
		accountCount: Object.keys(map).length,
	})
	return map
}

/**
 * Recursively scrub account identifiers from the provided data object.
 * Any property named "accountNumber" or "hashValue" will be removed and
 * replaced with an "accountDisplay" property using the provided display map.
 */
export function scrubAccountIdentifiers<T>(
	data: T,
	displayMap: AccountDisplayMap,
): UnknownScrubbed<T> {
	if (Array.isArray(data)) {
		return data.map((item) =>
			scrubAccountIdentifiers(item, displayMap),
		) as UnknownScrubbed<T>
	}
	if (data && typeof data === 'object') {
		const result: Record<string, any> = {}
		for (const [key, value] of Object.entries(data)) {
			if (key === 'accountNumber' || key === 'hashValue') {
				const display = displayMap[value as string]
				if (display) {
					result.accountDisplay = display
				}
				continue
			}
			result[key] = scrubAccountIdentifiers(value, displayMap)
		}
		return result as UnknownScrubbed<T>
	}
	if (typeof data === 'string' && displayMap[data]) {
		return displayMap[data] as UnknownScrubbed<T>
	}
	return data as UnknownScrubbed<T>
}
