import {
	GetInstrumentsRequestQueryParamsSchema,
	GetMarketHoursByMarketIdRequestParamsSchema,
	GetMarketHoursRequestQueryParamsSchema,
	GetMoversRequestParamsSchema,
	GetOptionChainRequestQueryParamsSchema,
	GetPriceHistoryRequestQueryParamsSchema,
} from '@sudowealth/schwab-api'
import type * as z from 'zod'
import { type ToolSpec } from '../types'

export const toolSpecs: ToolSpec<z.ZodSchema>[] = [
	{
		name: 'searchInstruments',
		description: 'Search for instruments',
		schema: GetInstrumentsRequestQueryParamsSchema,
		call: (c, p) =>
			c.marketData.instruments.getInstruments({
				queryParams: p,
			}),
	},
	{
		name: 'getMarketHours',
		description: 'Get market hours',
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
		description: 'Get market hours by market id',
		schema: GetMarketHoursByMarketIdRequestParamsSchema,
		call: (c, p) =>
			c.marketData.marketHours.getMarketHoursByMarketId({
				pathParams: { market_id: p.market_id },
				queryParams: { date: p.date },
			}),
	},
	{
		name: 'getMovers',
		description: 'Get movers',
		schema: GetMoversRequestParamsSchema,
		call: (c, p) =>
			c.marketData.movers.getMovers({
				pathParams: { symbol_id: p.symbol_id },
				queryParams: { sort: p.sort, frequency: p.frequency },
			}),
	},
	{
		name: 'getOptionChain',
		description: 'Get option chain',
		schema: GetOptionChainRequestQueryParamsSchema,
		call: (c, p) =>
			c.marketData.options.getOptionChain({
				queryParams: { symbol: p.symbol },
			}),
	},
	{
		name: 'getOptionExpirationChain',
		description: 'Get option expiration chain',
		schema: GetOptionChainRequestQueryParamsSchema,
		call: (c, p) =>
			c.marketData.options.getOptionExpirationChain({
				queryParams: { symbol: p.symbol },
			}),
	},
	{
		name: 'getPriceHistory',
		description: 'Get price history',
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
