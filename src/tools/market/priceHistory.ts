import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	GetPriceHistoryRequestQueryParamsSchema,
	type SchwabApiClient,
} from '@sudowealth/schwab-api'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'

export function registerPriceHistoryTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	logger.info(
		'[PriceHistoryTools] Attempting to register PriceHistory tools...',
	)
	createTool(client, server, {
		name: 'getPriceHistory',
		schema: GetPriceHistoryRequestQueryParamsSchema,
		handler: async (params, client) => {
			try {
				logger.info('[getPriceHistory] Fetching price history', {
					symbol: params.symbol,
					period: params.period,
					periodType: params.periodType,
					frequency: params.frequency,
					frequencyType: params.frequencyType,
				})

				const history = await client.marketData.priceHistory.getPriceHistory({
					queryParams: {
						symbol: params.symbol,
						period: params.period,
						periodType: params.periodType,
						frequency: params.frequency,
						frequencyType: params.frequencyType,
						startDate: params.startDate,
						endDate: params.endDate,
					},
				})

				const noHistory =
					history.empty || !history.candles || history.candles.length === 0

				return toolSuccess({
					data: history,
					message: noHistory
						? `No price history found for symbol: ${params.symbol} with the given parameters.`
						: `Successfully fetched price history for ${params.symbol}`,
					source: 'getPriceHistory',
				})
			} catch (error) {
				return toolError(error, {
					source: 'getPriceHistory',
					symbol: params.symbol,
				})
			}
		},
	})
	logger.info(
		'[PriceHistoryTools] PriceHistory tools registration process completed.',
	)
}
