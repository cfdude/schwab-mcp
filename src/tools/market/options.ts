import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { type SchwabApiClient } from '@sudowealth/schwab-api'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'

export function registerOptionsTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	logger.info('[OptionsTools] Attempting to register Options tools...')
	createTool(client, server, {
		name: 'getOptionChain',
		schema: client.schemas.GetOptionChainRequestQueryParamsSchema,
		handler: async (params, client) => {
			try {
				logger.info('[getOptionChain] Fetching option chain', {
					symbol: params.symbol,
				})

				const optionChain = await client.marketData.options.getOptionChain({
					queryParams: {
						symbol: params.symbol,
					},
				})

				const noOptionChain = !optionChain || optionChain.status !== 'SUCCESS'
				if (noOptionChain) {
					return toolError(
						`Could not fetch option chain for ${params.symbol}. Status: ${optionChain?.status}`,
						{ symbol: params.symbol },
					)
				}

				return toolSuccess({
					data: optionChain,
					message: `Successfully fetched option chain for ${params.symbol}`,
					source: 'getOptionChain',
				})
			} catch (error) {
				return toolError(error, {
					source: 'getOptionChain',
					symbol: params.symbol,
				})
			}
		},
	})

	createTool(client, server, {
		name: 'getOptionExpirationChain',
		schema: client.schemas.GetOptionExpirationChainRequestQueryParamsSchema,
		handler: async (params, client) => {
			try {
				const { symbol } = params
				logger.info(
					'[getOptionExpirationChain] Fetching option expiration chain',
					{ symbol },
				)

				const expirationChain =
					await client.marketData.options.getOptionExpirationChain({
						queryParams: { symbol },
					})

				if (!expirationChain) {
					return toolError(
						`Could not fetch option expiration chain for ${symbol}.`,
						{ symbol },
					)
				}

				return toolSuccess({
					data: expirationChain,
					message: `Successfully fetched option expiration chain for ${symbol}`,
					source: 'getOptionExpirationChain',
				})
			} catch (error) {
				return toolError(error, {
					source: 'getOptionExpirationChain',
					symbol: params.symbol,
				})
			}
		},
	})
	logger.info('[OptionsTools] Options tools registration process completed.')
}
