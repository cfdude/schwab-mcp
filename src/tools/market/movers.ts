import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	GetMoversRequestParamsSchema,
	type SchwabApiClient,
} from '@sudowealth/schwab-api'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'

export function registerMoversTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	logger.info('[MoversTools] Attempting to register Movers tools...')
	createTool(client, server, {
		name: 'getMovers',
		schema: GetMoversRequestParamsSchema,
		handler: async ({ symbol_id, sort, frequency }, client) => {
			try {
				logger.info('[getMovers] Fetching movers', {
					symbol_id,
					sort,
					frequency,
				})

				const movers = await client.marketData.movers.getMovers({
					pathParams: { symbol_id },
					queryParams: { sort, frequency },
				})

				const noMovers =
					!movers || !movers.screeners || movers.screeners.length === 0

				return toolSuccess({
					data: movers.screeners,
					message: noMovers
						? `No movers found for symbol: ${symbol_id}.`
						: `Successfully fetched movers for ${symbol_id}`,
					source: 'getMovers',
				})
			} catch (error) {
				return toolError(error, { source: 'getMovers', symbol_id })
			}
		},
	})
	logger.info('[MoversTools] Movers tools registration process completed.')
}
