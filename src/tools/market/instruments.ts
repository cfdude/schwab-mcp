import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	GetInstrumentsRequestQueryParamsSchema,
	type SchwabApiClient,
} from '@sudowealth/schwab-api'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'

export function registerInstrumentTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	logger.info('[InstrumentTools] Attempting to register Instrument tools...')
	createTool(client, server, {
		name: 'searchInstruments',
		schema: GetInstrumentsRequestQueryParamsSchema,
		handler: async ({ symbol, projection }, client) => {
			try {
				logger.info('[searchInstruments] Fetching instruments', {
					symbol,
					projection,
				})

				const instruments = await client.marketData.instruments.getInstruments({
					queryParams: { symbol, projection },
				})

				return toolSuccess({
					source: 'searchInstruments',
					data: instruments,
					message:
						Array.isArray(instruments) && instruments.length > 0
							? `Successfully fetched instruments for symbol: ${symbol}`
							: `No instruments found for symbol: ${symbol} with projection: ${projection}.`,
				})
			} catch (error) {
				return toolError(error, {
					source: 'searchInstruments',
					symbol,
					projection,
				})
			}
		},
	})
	logger.info(
		'[InstrumentTools] Instrument tools registration process completed.',
	)
}
