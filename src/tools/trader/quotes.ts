import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { type SchwabApiClient } from '@sudowealth/schwab-api'
import { z } from 'zod'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'
import { mergeShapes } from '../../shared/utils'

export function registerQuotesTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	logger.info('[QuotesTools] Attempting to register Quotes tools...');
	createTool(client, server, {
		name: 'getQuotes',
		schema: client.schemas.GetQuotesRequestQueryParamsSchema,
		handler: async ({ symbols, fields, indicative }, client) => {
			try {
				logger.info('[getQuotes] Fetching quotes', { symbols, fields })

				const quotesData = await client.marketData.quotes.getQuotes({
					queryParams: { symbols, fields, indicative },
				})

				const noQuotes = Object.keys(quotesData).length === 0

				return toolSuccess({
					data: quotesData,
					message: noQuotes
						? `No quotes found for symbols: ${symbols}.`
						: `Successfully fetched quotes for ${symbols}`,
					source: 'getQuotes',
				})
			} catch (error) {
				return toolError(error, { source: 'getQuotes', symbols })
			}
		},
	})

	createTool(client, server, {
		name: 'getQuoteBySymbolId',
		schema: z.object(
			mergeShapes(
				client.schemas.GetQuoteBySymbolIdRequestPathParamsSchema.shape,
				client.schemas.GetQuoteBySymbolIdRequestQueryParamsSchema.shape,
			),
		),
		handler: async ({ symbol_id, fields }, client) => {
			try {
				logger.info('[getQuoteBySymbolId] Fetching quote', {
					symbol_id,
					fields,
				})

				const quoteData = await client.marketData.quotes.getQuoteBySymbolId({
					pathParams: { symbol_id },
					queryParams: { fields },
				})

				const noQuote =
					!quoteData ||
					Object.keys(quoteData).length === 0 ||
					!quoteData[symbol_id.toUpperCase()]

				return toolSuccess({
					data: quoteData[symbol_id.toUpperCase()],
					message: noQuote
						? `No quote found for symbol: ${symbol_id}.`
						: `Successfully fetched quote for ${symbol_id}`,
					source: 'getQuoteBySymbolId',
				})
			} catch (error) {
				return toolError(error, { source: 'getQuoteBySymbolId', symbol_id })
			}
		},
	})
	logger.info('[QuotesTools] Quotes tools registration process completed.');
}
