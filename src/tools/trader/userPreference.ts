import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { type SchwabApiClient } from '@sudowealth/schwab-api'
import z from 'zod'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'

export function registerUserPreferenceTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	logger.info(
		'[UserPreferenceTools] Attempting to register User preference tools...',
	)
	createTool(client, server, {
		name: 'getUserPreference',
		schema: z.object({}),
		handler: async (_, client) => {
			try {
				logger.info('[getUserPreference] Fetching user preference')

				const userPreference =
					await client.trader.userPreference.getUserPreference()
				if (userPreference.streamerInfo.length === 0) {
					return toolSuccess({
						data: [],
						message: 'User preference not found.',
						source: 'getUserPreference',
					})
				}

				logger.info('[getUserPreference] Fetching user preference', {
					userPreference,
				})

				logger.debug('[getUserPreference] User preference', {
					userPreference,
				})

				return toolSuccess({
					data: userPreference,
					message: 'Successfully fetched user preference',
					source: 'getUserPreference',
				})
			} catch (error) {
				return toolError(error, { source: 'getUserPreference' })
			}
		},
	})
	logger.info(
		'[UserPreferenceTools] User preference tools registration process completed.',
	)
}
