import {
	buildAccountDisplayMap,
	scrubAccountIdentifiers,
	GetAccountByNumberParams,
	GetAccountNumbersParams,
	GetOrdersParams,
	GetAccountsParams,
	PlaceOrderParams,
	GetOrderByIdParams,
	CancelOrderParams,
	ReplaceOrderParams,
	GetTransactionsParams,
	GetTransactionByIdParams,
	GetUserPreferenceParams,
	type SchwabApiClient,
} from '@sudowealth/schwab-api'
import { z } from 'zod'
import { logger } from '../../shared/log'
import { createToolSpec } from '../types'

/**
 * Filter orders by ticker symbol (case-insensitive).
 * Matches against instrument.symbol in any leg of the order.
 */
function filterOrdersBySymbol(orders: any[], symbol: string): any[] {
	const upperSymbol = symbol.toUpperCase()
	return orders.filter((order: any) =>
		order.orderLegCollection?.some(
			(leg: any) =>
				leg.instrument?.symbol?.toUpperCase() === upperSymbol,
		),
	)
}

/**
 * Build a map of raw numeric accountNumber → encrypted hashValue.
 * This lets us enrich orders with the hash the AI needs for follow-up calls.
 */
async function buildAccountHashMap(
	client: SchwabApiClient,
): Promise<Record<string, string>> {
	const accounts = await client.trader.accounts.getAccountNumbers()
	const map: Record<string, string> = {}
	for (const acc of accounts) {
		map[acc.accountNumber] = acc.hashValue
	}
	return map
}

/**
 * Process orders: scrub sensitive data, then add accountHash afterward.
 * Adding accountHash AFTER scrubbing prevents the scrubber from replacing
 * the hash value with the display name (since hashes are in the display map).
 *
 * Every order in the output will have:
 * - accountHash: encrypted ID for API calls (cancelOrder, replaceOrder, etc.)
 * - accountDisplay: friendly name for user display (e.g., "Rob stock ...964")
 */
async function processOrders(
	client: SchwabApiClient,
	orders: any[],
): Promise<any> {
	// Capture raw accountNumber → hash mapping BEFORE scrubbing removes them
	const hashMap = await buildAccountHashMap(client)
	const orderHashLookup = orders.map((order: any) =>
		hashMap[String(order.accountNumber)],
	)

	// Scrub removes raw accountNumber, adds accountDisplay
	const displayMap = await buildAccountDisplayMap(client)
	const scrubbed = scrubAccountIdentifiers(orders, displayMap) as any[]

	// Add accountHash AFTER scrubbing so it doesn't get replaced
	return scrubbed.map((order: any, i: number) => ({
		accountHash: orderHashLookup[i],
		...order,
	}))
}

/** Extended getOrders params with optional symbol filter and optional account */
const GetOrdersWithFilterParams = GetOrdersParams.extend({
	symbol: z
		.string()
		.optional()
		.describe(
			'Filter orders by ticker symbol (e.g., AAPL, LRCX). Client-side filter applied after fetch.',
		),
	accountNumber: z
		.string()
		.optional()
		.describe(
			'Encrypted account number. If provided, only returns orders for this account.',
		),
})

export const toolSpecs = [
	createToolSpec({
		name: 'getAccounts',
		description: 'Get accounts',
		schema: GetAccountsParams,
		call: async (c, p) => {
			logger.info('[getAccounts] Fetching accounts', {
				showPositions: p?.fields,
			})
			const accounts = await c.trader.accounts.getAccounts({
				queryParams: { fields: p?.fields },
			})
			const accountSummaries = accounts.map((acc) => ({
				...acc.securitiesAccount,
			}))
			const displayMap = await buildAccountDisplayMap(c)
			return scrubAccountIdentifiers(accountSummaries, displayMap)
		},
	}),
	createToolSpec({
		name: 'getAccountNumbers',
		description: 'Get account numbers',
		schema: GetAccountNumbersParams,
		call: async (c, p) => {
			logger.info('[getAccountNumbers] Fetching account numbers')
			const accounts = await c.trader.accounts.getAccountNumbers(p)
			const displayMap = await buildAccountDisplayMap(c)
			return accounts.map((acc) => {
				return {
					accountDisplay: displayMap[acc.accountNumber],
					hashValue: acc.hashValue,
				}
			})
		},
	}),
	createToolSpec({
		name: 'getAccount',
		description: 'Get account',
		schema: GetAccountByNumberParams,
		call: async (c, p) => {
			const account = await c.trader.accounts.getAccountByNumber({
				pathParams: { accountNumber: p.accountNumber },
			})
			const displayMap = await buildAccountDisplayMap(c)
			return scrubAccountIdentifiers(account, displayMap)
		},
	}),
	createToolSpec({
		name: 'getOrders',
		description:
			'Get orders. Optionally filter by account number and/or ticker symbol to reduce response size.',
		schema: GetOrdersWithFilterParams,
		call: async (c, p) => {
			const { symbol, accountNumber, ...queryParams } = p
			logger.info('[getOrders] Fetching orders', {
				maxResults: queryParams.maxResults,
				hasDateFilter: !!queryParams.fromEnteredTime || !!queryParams.toEnteredTime,
				symbol: symbol || 'all',
				accountScoped: !!accountNumber,
			})

			let orders: any[]
			if (accountNumber) {
				orders = await c.trader.orders.getOrdersByAccount({
					pathParams: { accountNumber },
					queryParams,
				})
			} else {
				orders = await c.trader.orders.getOrders({ queryParams })
			}

			if (symbol) {
				const preFilterCount = orders.length
				orders = filterOrdersBySymbol(orders, symbol)
				logger.info('[getOrders] Symbol filter applied', {
					symbol,
					before: preFilterCount,
					after: orders.length,
				})
			}

			return processOrders(c, orders)
		},
	}),
	createToolSpec({
		name: 'placeOrder',
		description: 'Place order for a specific account',
		schema: PlaceOrderParams,
		call: async (c, p) => {
			const order = await c.trader.orders.placeOrderForAccount({
				pathParams: { accountNumber: p.accountNumber },
				body: p,
			})
			const displayMap = await buildAccountDisplayMap(c)
			return scrubAccountIdentifiers(order, displayMap)
		},
	}),
	createToolSpec({
		name: 'getOrder',
		description: 'Get order by order id for a specific account',
		schema: GetOrderByIdParams,
		call: async (c, p) => {
			const order = await c.trader.orders.getOrderByOrderId({
				pathParams: { accountNumber: p.accountNumber, orderId: p.orderId },
			})
			return processOrders(c, [order]).then((orders: any[]) => orders[0])
		},
	}),
	createToolSpec({
		name: 'cancelOrder',
		description: 'Cancel order by order id for a specific account',
		schema: CancelOrderParams,
		call: async (c, p) => {
			const order = await c.trader.orders.cancelOrder({
				pathParams: { accountNumber: p.accountNumber, orderId: p.orderId },
			})
			const displayMap = await buildAccountDisplayMap(c)
			return scrubAccountIdentifiers(order, displayMap)
		},
	}),
	createToolSpec({
		name: 'replaceOrder',
		description: 'Replace order by order id for a specific account',
		schema: ReplaceOrderParams,
		call: async (c, p) => {
			const order = await c.trader.orders.replaceOrder({
				pathParams: { accountNumber: p.accountNumber, orderId: p.orderId },
				body: p,
			})
			const displayMap = await buildAccountDisplayMap(c)
			return scrubAccountIdentifiers(order, displayMap)
		},
	}),
	createToolSpec({
		name: 'getTransactions',
		description: 'Get transactions',
		schema: GetTransactionsParams,
		call: async (c, p) => {
			logger.info('[getTransactions] Fetching accounts')
			const accounts = await c.trader.accounts.getAccountNumbers()
			if (accounts.length === 0) return []
			logger.info('[getTransactions] Fetching transactions', {
				accountCount: accounts.length,
				startDate: p.startDate,
				endDate: p.endDate,
				hasType: !!p.types,
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
			const displayMap = await buildAccountDisplayMap(c)
			return scrubAccountIdentifiers(transactions, displayMap)
		},
	}),
	createToolSpec({
		name: 'getTransaction',
		description: 'Get transaction',
		schema: GetTransactionByIdParams,
		call: async (c, p) => {
			logger.info('[getTransaction] Fetching transaction', {
				transactionId: p.transactionId,
			})
		},
	}),
	createToolSpec({
		name: 'getUserPreference',
		description: 'Get user preference',
		schema: GetUserPreferenceParams,
		call: async (c, p) => {
			logger.info('[getUserPreference] Fetching user preference')
			const userPreference = await c.trader.userPreference.getUserPreference(p)
			if (userPreference.streamerInfo.length === 0) {
				return []
			}
			logger.info('[getUserPreference] User preference fetched', {
				hasAccounts: userPreference.accounts?.length > 0,
				accountCount: userPreference.accounts?.length || 0,
				hasStreamerInfo: userPreference.streamerInfo?.length > 0,
			})
			const displayMap = await buildAccountDisplayMap(c)
			return scrubAccountIdentifiers(userPreference, displayMap)
		},
	}),
] as const
