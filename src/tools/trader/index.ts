import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import {
	type SchwabApiClient,
	GetAccountsRequestQueryParams,
	GetOrdersRequestQueryParams,
	GetQuotesRequestQueryParamsSchema,
	GetQuoteBySymbolIdRequestParamsSchema,
	GetTransactionsRequestQueryParams,
} from '@sudowealth/schwab-api'
import z from 'zod'
import {
	buildAccountDisplayMap,
	scrubAccountIdentifiers,
} from '../../shared/accountScrubber'
import { logger } from '../../shared/logger'
import { createTool, toolError, toolSuccess } from '../../shared/toolBuilder'

interface ToolSpec<S extends z.ZodSchema> {
	name: string
	schema: S
	call: (client: SchwabApiClient, params: z.infer<S>) => Promise<any>
}

const TRADER_TOOLS: ToolSpec<any>[] = [
	{
		name: 'getAccounts',
		schema: GetAccountsRequestQueryParams,
		call: async (c, p) => {
			logger.info('[getAccounts] Fetching accounts', {
				showPositions: p?.fields,
			})
			const displayMap = await buildAccountDisplayMap(c)
			const accounts = await c.trader.accounts.getAccounts({
				queryParams: { fields: p?.fields },
			})
			const accountSummaries = accounts.map((acc: any) => ({
				...acc.securitiesAccount,
			}))
			return scrubAccountIdentifiers(accountSummaries, displayMap)
		},
	},
	{
		name: 'getAccountNumbers',
		schema: z.object({}),
		call: async (c) => {
			logger.info('[getAccountNumbers] Fetching account numbers')
			const displayMap = await buildAccountDisplayMap(c)
			const accounts = await c.trader.accounts.getAccountNumbers()
			return accounts.map((acc) => displayMap[acc.accountNumber])
		},
	},
	{
		name: 'getOrders',
		schema: GetOrdersRequestQueryParams,
		call: async (c, p) => {
			logger.info('[getOrders] Fetching orders', {
				maxResults: p.maxResults,
				hasDateFilter: !!p.fromEnteredTime || !!p.toEnteredTime,
			})
			const displayMap = await buildAccountDisplayMap(c)
			const orders = await c.trader.orders.getOrders({ queryParams: p })
			return scrubAccountIdentifiers(orders, displayMap)
		},
	},
	{
		name: 'getQuotes',
		schema: GetQuotesRequestQueryParamsSchema,
		call: async (c, p) => {
			logger.info('[getQuotes] Fetching quotes', {
				symbols: p.symbols,
				fields: p.fields,
			})
			return c.marketData.quotes.getQuotes({
				queryParams: {
					symbols: p.symbols,
					fields: p.fields,
					indicative: p.indicative,
				},
			})
		},
	},
	{
		name: 'getQuoteBySymbolId',
		schema: GetQuoteBySymbolIdRequestParamsSchema,
		call: async (c, p) => {
			logger.info('[getQuoteBySymbolId] Fetching quote', {
				symbol_id: p.symbol_id,
				fields: p.fields,
			})
			const quoteData = await c.marketData.quotes.getQuoteBySymbolId({
				pathParams: { symbol_id: p.symbol_id },
				queryParams: { fields: p.fields },
			})
			return quoteData[p.symbol_id.toUpperCase()]
		},
	},
	{
		name: 'getTransactions',
		schema: GetTransactionsRequestQueryParams,
		call: async (c, p) => {
			logger.info('[getTransactions] Fetching accounts')
			const displayMap = await buildAccountDisplayMap(c)
			const accounts = await c.trader.accounts.getAccountNumbers()
			if (accounts.length === 0) {
				return []
			}
			logger.info('[getTransactions] Fetching transactions', {
				accountCount: accounts.length,
				startDate: p.startDate,
				endDate: p.endDate,
				hasTypes: !!p.types,
				symbol: p.symbol,
			})
			const transactions: any[] = []
			for (const account of accounts) {
				const accountTransactions = await c.trader.transactions.getTransactions(
					{
						pathParams: { accountNumber: account.hashValue },
						queryParams: {
							startDate: p.startDate,
							endDate: p.endDate,
							types: p.types,
							symbol: p.symbol,
						},
					},
				)
				logger.debug('[getTransactions] Transactions for account', {
					accountHash: account.hashValue,
					count: accountTransactions.length,
				})
				transactions.push(...accountTransactions)
			}
			return scrubAccountIdentifiers(transactions, displayMap)
		},
	},
	{
		name: 'getUserPreference',
		schema: z.object({}),
		call: async (c) => {
			logger.info('[getUserPreference] Fetching user preference')
			const userPreference = await c.trader.userPreference.getUserPreference()
			const displayMap = await buildAccountDisplayMap(c)
			if (userPreference.streamerInfo.length === 0) {
				return []
			}
			logger.info('[getUserPreference] Fetching user preference', {
				userPreference,
			})
			logger.debug('[getUserPreference] User preference', { userPreference })
			return scrubAccountIdentifiers(userPreference, displayMap)
		},
	},
]

export function registerTraderTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	TRADER_TOOLS.forEach((spec) => {
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
