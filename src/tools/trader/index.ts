import {
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
import { type ToolSpec } from '../types'

export const toolSpecs: ToolSpec<z.ZodSchema>[] = [
	{
		name: 'getAccounts',
		description: 'Get accounts',
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
		description: 'Get account numbers',
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
		description: 'Get orders',
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
		description: 'Get quotes',
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
		description: 'Get quote by symbol id',
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
		description: 'Get transactions',
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
			const transactions: unknown[] = []
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
		description: 'Get user preference',
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
