import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { type SchwabApiClient } from '@sudowealth/schwab-api'
import { logger } from '../../shared/logger'
import { createTool, toolSuccess, toolError } from '../../shared/toolBuilder'

export function registerTransactionTools(
	client: SchwabApiClient,
	server: McpServer,
) {
	logger.info('[TransactionTools] Attempting to register Transaction tools...');
	createTool(client, server, {
		name: 'getTransactions',
		schema: client.schemas.GetTransactionsRequestQueryParams,
		handler: async ({ startDate, endDate, types, symbol }, client) => {
			try {
				logger.info('[getTransactions] Fetching accounts')

				// First get all account numbers
				const accounts = await client.trader.accounts.getAccountNumbers()
				if (accounts.length === 0) {
					return toolSuccess({
						data: [],
						message: 'No Schwab accounts found.',
						source: 'getTransactions',
					})
				}

				logger.info('[getTransactions] Fetching transactions', {
					accountCount: accounts.length,
					startDate,
					endDate,
					hasTypes: !!types,
					symbol,
				})

				const transactions: any[] = []
				for (const account of accounts) {
					const accountTransactions =
						await client.trader.transactions.getTransactions({
							pathParams: { accountNumber: account.hashValue },
							queryParams: {
								startDate,
								endDate,
								types,
								symbol,
							},
						})
					logger.debug('[getTransactions] Transactions for account', {
						accountHash: account.hashValue,
						count: accountTransactions.length,
					})
					transactions.push(...accountTransactions)
				}

				return toolSuccess({
					data: transactions,
					message:
						transactions.length === 0
							? 'No Schwab transactions found.'
							: 'Successfully fetched Schwab transactions',
					source: 'getTransactions',
				})
			} catch (error) {
				return toolError(error, { source: 'getTransactions' })
			}
		},
	})
	logger.info('[TransactionTools] Transaction tools registration process completed.');
}
