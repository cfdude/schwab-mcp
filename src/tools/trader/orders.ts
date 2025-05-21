import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	GetOrdersRequestQueryParams,
	type SchwabApiClient,
} from '@sudowealth/schwab-api'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'

export function registerOrderTools(client: SchwabApiClient, server: McpServer) {
	logger.info('[OrderTools] Attempting to register Order tools...')
	createTool(client, server, {
		name: 'getOrders',
		schema: GetOrdersRequestQueryParams,
		handler: async (queryParams, client) => {
			try {
				logger.info('[getOrders] Fetching orders', {
					maxResults: queryParams.maxResults,
					hasDateFilter:
						!!queryParams.fromEnteredTime || !!queryParams.toEnteredTime,
				})

				const orders = await client.trader.orders.getOrders({ queryParams })

				return toolSuccess({
					data: orders,
					message:
						orders.length === 0
							? 'No Schwab orders found.'
							: 'Successfully fetched Schwab orders',
					source: 'getOrders',
				})
			} catch (error) {
				return toolError(error, { source: 'getOrders' })
			}
		},
	})
	logger.info('[OrderTools] Order tools registration process completed.')
}
