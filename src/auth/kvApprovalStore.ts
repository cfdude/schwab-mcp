// Using any for KVNamespace to avoid type conflicts between workers-types versions
import { APPROVED_CLIENTS_KEY, TTL_1_YEAR, LOGGER_CONTEXTS } from '../shared/constants'
import { logger } from '../shared/log'

const approvalLogger = logger.child(LOGGER_CONTEXTS.KV_APPROVAL_STORE)

/**
 * KV-based approval store for approved client IDs.
 * This replaces the cookie-based approach to persist approvals across all sessions.
 */

export async function isClientApproved(
	kv: any, // KVNamespace
	clientId: string,
): Promise<boolean> {
	if (!clientId) return false

	try {
		const approvedClients = await getApprovedClients(kv)
		const isApproved = approvedClients.includes(clientId)

		approvalLogger.debug('Checking client approval', {
			clientId: clientId.substring(0, 8) + '...',
			isApproved,
			totalApproved: approvedClients.length,
		})

		return isApproved
	} catch (error) {
		approvalLogger.error('Error checking client approval', { error })
		return false
	}
}

export async function approveClient(
	kv: any, // KVNamespace
	clientId: string,
): Promise<void> {
	if (!clientId) return

	try {
		const approvedClients = await getApprovedClients(kv)

		if (approvedClients.includes(clientId)) {
			approvalLogger.debug('Client already approved', {
				clientId: clientId.substring(0, 8) + '...',
			})
			return
		}

		const updatedClients = [...approvedClients, clientId]

		await kv.put(APPROVED_CLIENTS_KEY, JSON.stringify(updatedClients), {
			expirationTtl: TTL_1_YEAR,
		})

		approvalLogger.info('Client approved and stored in KV', {
			clientId: clientId.substring(0, 8) + '...',
			totalApproved: updatedClients.length,
		})
	} catch (error) {
		approvalLogger.error('Error approving client', { error })
		throw error
	}
}

async function getApprovedClients(kv: any): Promise<string[]> {
	try {
		const data = await kv.get(APPROVED_CLIENTS_KEY)
		if (!data) return []

		const parsed = JSON.parse(data)
		if (!Array.isArray(parsed)) return []

		return parsed.filter((id): id is string => typeof id === 'string')
	} catch (error) {
		approvalLogger.warn('Error reading approved clients from KV', { error })
		return []
	}
}
