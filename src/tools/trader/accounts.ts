import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	GetAccountsRequestQueryParams,
	type SchwabApiClient,
} from '@sudowealth/schwab-api'
import { z } from 'zod'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'

export function registerAccountTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	logger.info('[AccountTools] Attempting to register account tools...')
	createTool(client, server, {
		name: 'getAccounts',
		schema: GetAccountsRequestQueryParams,
		handler: async (queryParams, client) => {
			try {
				logger.info('Fetching accounts', {
					showPositions: queryParams?.fields,
				})
				const accounts = await client.trader.accounts.getAccounts({
					queryParams: { fields: queryParams?.fields },
				})

				const accountSummaries = accounts.map((acc: any) => ({
					...acc.securitiesAccount,
				}))

				return toolSuccess({
					data: accountSummaries,
					message:
						accounts.length > 0
							? 'Successfully fetched Schwab accounts'
							: 'No Schwab accounts found',
					source: 'getAccounts',
				})
			} catch (error) {
				return toolError(error, { source: 'getAccounts' })
			}
		},
	})

	createTool(client, server, {
		name: 'getAccountNumbers',
		schema: z.object({}),
		handler: async (_params, client) => {
			try {
				logger.info('Fetching account numbers')
				const accounts = await client.trader.accounts.getAccountNumbers()

				return toolSuccess({
					data: accounts,
					message:
						accounts.length > 0
							? 'Successfully fetched Schwab accounts'
							: 'No Schwab accounts found',
					source: 'getAccountNumbers',
				})
			} catch (error) {
				return toolError(error, { source: 'getAccountNumbers' })
			}
		},
	})

	logger.info('[AccountTools] Account tools registration process completed.')
}
