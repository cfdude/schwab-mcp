import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	type SchwabApiClient,
	GetInstrumentsRequestQueryParamsSchema,
	GetMarketHoursByMarketIdRequestParamsSchema,
	GetMarketHoursRequestQueryParamsSchema,
	GetMoversRequestParamsSchema,
	GetOptionChainRequestQueryParamsSchema,
	GetPriceHistoryRequestQueryParamsSchema,
} from '@sudowealth/schwab-api'
import type * as z from 'zod'
import { createTool, toolError, toolSuccess } from '../../shared/toolBuilder'

interface ToolSpec<S extends z.ZodSchema<any, any>> {
	name: string
	schema: S
	call: (client: SchwabApiClient, params: z.infer<S>) => Promise<any>
}

const MARKET_TOOLS: ToolSpec<any>[] = [
	{
		name: 'searchInstruments',
		schema: GetInstrumentsRequestQueryParamsSchema,
		call: (c, p) =>
			c.marketData.instruments.getInstruments({
				queryParams: p,
			}),
	},
	{
		name: 'getMarketHours',
		schema: GetMarketHoursRequestQueryParamsSchema,
		call: (c, p) =>
			c.marketData.marketHours.getMarketHours({
				queryParams: {
					markets: p.markets,
					date: p.date ? new Date(p.date).toISOString() : undefined,
				},
			}),
	},
	{
		name: 'getMarketHoursByMarketId',
		schema: GetMarketHoursByMarketIdRequestParamsSchema,
		call: (c, p) =>
			c.marketData.marketHours.getMarketHoursByMarketId({
				pathParams: { market_id: p.market_id },
				queryParams: { date: p.date },
			}),
	},
	{
		name: 'getMovers',
		schema: GetMoversRequestParamsSchema,
		call: (c, p) =>
			c.marketData.movers.getMovers({
				pathParams: { symbol_id: p.symbol_id },
				queryParams: { sort: p.sort, frequency: p.frequency },
			}),
	},
	{
		name: 'getOptionChain',
		schema: GetOptionChainRequestQueryParamsSchema,
		call: (c, p) =>
			c.marketData.options.getOptionChain({
				queryParams: { symbol: p.symbol },
			}),
	},
	{
		name: 'getOptionExpirationChain',
		schema: GetOptionChainRequestQueryParamsSchema,
		call: (c, p) =>
			c.marketData.options.getOptionExpirationChain({
				queryParams: { symbol: p.symbol },
			}),
	},
	{
		name: 'getPriceHistory',
		schema: GetPriceHistoryRequestQueryParamsSchema,
		call: (c, p) =>
			c.marketData.priceHistory.getPriceHistory({
				queryParams: {
					symbol: p.symbol,
					period: p.period,
					periodType: p.periodType,
					frequency: p.frequency,
					frequencyType: p.frequencyType,
					startDate: p.startDate,
					endDate: p.endDate,
				},
			}),
	},
]

export function registerMarketTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	MARKET_TOOLS.forEach((spec) => {
		createTool(client, server, {
			name: spec.name,
			schema: spec.schema,
			handler: async (params, c) => {
				try {
					const data = await spec.call(c, params as any)
					return toolSuccess({
						data,
						source: spec.name,
						message: `Successfully executed ${spec.name}`,
					})
				} catch (error) {
					return toolError(error, { source: spec.name })
				}
			},
		})
	})
}
