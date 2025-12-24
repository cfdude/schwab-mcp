/**
 * Direct REST API handler for Python/external script access
 *
 * This bypasses the MCP OAuth layer and uses API key authentication,
 * allowing scripts to access Schwab data without a live Claude Code session.
 *
 * Security:
 * - API key stored as Cloudflare secret (never in code)
 * - Timing-safe comparison to prevent timing attacks
 * - Generic 401 responses to avoid information leakage
 * - All requests logged for monitoring
 * - HTTPS enforced by Cloudflare
 */

import {
	createApiClient,
	type SchwabApiClient,
	type TokenData,
} from '@sudowealth/schwab-api'
import { Hono } from 'hono'
import { type Env } from '../../types/env'
import { initializeSchwabAuthClient } from '../auth/client'
import { getConfig } from '../config'
import { LOGGER_CONTEXTS, ENVIRONMENTS } from '../shared/constants'
import { makeKvTokenStore } from '../shared/kvTokenStore'
import { logger } from '../shared/log'

// Create Hono app for API routes with /api basePath
const api = new Hono<{ Bindings: Env }>().basePath('/api')

// Create a scoped logger for API handlers
const apiLogger = logger.child(
	LOGGER_CONTEXTS.API || { contextId: 'api-handler' },
)

/**
 * Timing-safe API key comparison to prevent timing attacks
 * Uses constant-time comparison that always checks all bytes
 */
function validateApiKey(provided: string, expected: string): boolean {
	if (!provided || !expected) {
		return false
	}

	// Convert to Uint8Array for byte-by-byte comparison
	const encoder = new TextEncoder()
	const providedBytes = encoder.encode(provided)
	const expectedBytes = encoder.encode(expected)

	// Always compare against expected length to prevent length oracle
	const maxLen = Math.max(providedBytes.length, expectedBytes.length)

	let result = 0

	// XOR each byte - any difference will set bits in result
	// Always iterate through all bytes to maintain constant time
	for (let i = 0; i < maxLen; i++) {
		const a = providedBytes[i] ?? 0
		const b = expectedBytes[i] ?? 0
		result |= a ^ b
	}

	// Also check length mismatch
	result |= providedBytes.length ^ expectedBytes.length

	return result === 0
}

/**
 * Extract API key from Authorization header
 * Supports: "Bearer <key>" or just "<key>"
 */
function extractApiKey(authHeader: string | null): string | null {
	if (!authHeader) {
		return null
	}

	if (authHeader.startsWith('Bearer ')) {
		return authHeader.slice(7)
	}

	return authHeader
}

/**
 * API Key authentication middleware
 */
async function authenticateApiKey(c: any, next: () => Promise<void>) {
	const config = getConfig(c.env)
	const apiSecretKey = config.API_SECRET_KEY

	if (!apiSecretKey) {
		apiLogger.error('API_SECRET_KEY not configured')
		return c.json({ error: 'API not configured' }, 503)
	}

	const authHeader = c.req.header('Authorization')
	const providedKey = extractApiKey(authHeader)

	if (!providedKey || !validateApiKey(providedKey, apiSecretKey)) {
		apiLogger.warn('Invalid API key attempt', {
			ip: c.req.header('CF-Connecting-IP') || 'unknown',
			userAgent: c.req.header('User-Agent')?.substring(0, 50) || 'unknown',
		})
		// Generic error - don't reveal if key exists or is close
		return c.json({ error: 'Unauthorized' }, 401)
	}

	apiLogger.info('API key authentication successful', {
		ip: c.req.header('CF-Connecting-IP') || 'unknown',
	})

	await next()
}

/**
 * Create an authenticated Schwab API client using tokens from KV
 */
async function createAuthenticatedClient(
	env: Env,
): Promise<SchwabApiClient | null> {
	const config = getConfig(env)
	const kvToken = makeKvTokenStore(config.OAUTH_KV)

	// Load tokens from stable SCHWAB_CLIENT_ID key
	const tokenData = await kvToken.load({ clientId: config.SCHWAB_CLIENT_ID })

	if (!tokenData) {
		apiLogger.warn('No Schwab tokens found in KV')
		return null
	}

	// Check if tokens are expired
	const now = Date.now()
	const bufferMs = 5 * 60 * 1000 // 5 minutes buffer
	const isExpired = tokenData.expiresAt < now + bufferMs

	if (isExpired && !tokenData.refreshToken) {
		apiLogger.warn('Schwab tokens expired and no refresh token available')
		return null
	}

	// Create token manager with KV persistence
	const saveToken = async (data: TokenData) => {
		await kvToken.save({ clientId: config.SCHWAB_CLIENT_ID }, data)
		apiLogger.debug('Token refreshed and saved to KV')
	}

	const loadToken = async (): Promise<TokenData | null> => {
		return await kvToken.load({ clientId: config.SCHWAB_CLIENT_ID })
	}

	const tokenManager = initializeSchwabAuthClient(
		config,
		config.SCHWAB_REDIRECT_URI,
		loadToken,
		saveToken,
	)

	// Initialize token manager to load tokens
	await tokenManager.initialize()

	// Create and return the API client
	const client = createApiClient({
		config: {
			environment: ENVIRONMENTS.PRODUCTION,
			enableLogging: true,
			logLevel: 'error',
		},
		auth: tokenManager,
	})

	return client
}

/**
 * Wrap API calls with error handling
 */
async function handleApiCall<T>(
	c: any,
	operation: string,
	fn: (client: SchwabApiClient) => Promise<T>,
): Promise<Response> {
	try {
		const client = await createAuthenticatedClient(c.env)

		if (!client) {
			return c.json(
				{
					error: 'Schwab authentication required',
					message:
						'No valid Schwab tokens found. Please authenticate via Claude Code first.',
					code: 'AUTH_REQUIRED',
				},
				401,
			)
		}

		const result = await fn(client)

		apiLogger.info(`API call successful: ${operation}`)
		return c.json(result)
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error)

		// Check for auth-related errors
		if (
			message.includes('401') ||
			message.includes('Unauthorized') ||
			message.includes('token')
		) {
			apiLogger.warn(`API auth error: ${operation}`, { error: message })
			return c.json(
				{
					error: 'Schwab authentication expired',
					message:
						'Schwab tokens have expired. Please re-authenticate via Claude Code.',
					code: 'AUTH_EXPIRED',
				},
				401,
			)
		}

		apiLogger.error(`API call failed: ${operation}`, { error: message })
		return c.json(
			{
				error: 'API call failed',
				message,
				code: 'API_ERROR',
			},
			500,
		)
	}
}

// Apply authentication middleware to all /api routes
api.use('*', authenticateApiKey)

/**
 * GET /api/status - Check API and token status
 */
api.get('/status', async (c) => {
	const config = getConfig(c.env)
	const kvToken = makeKvTokenStore(config.OAUTH_KV)

	const tokenData = await kvToken.load({ clientId: config.SCHWAB_CLIENT_ID })

	if (!tokenData) {
		return c.json({
			status: 'no_tokens',
			message: 'No Schwab tokens found. Please authenticate via Claude Code.',
			authenticated: false,
		})
	}

	const now = Date.now()
	const expiresAt = tokenData.expiresAt
	const isExpired = expiresAt < now
	const expiresIn = Math.max(0, Math.floor((expiresAt - now) / 1000))

	return c.json({
		status: isExpired ? 'expired' : 'valid',
		authenticated: !isExpired,
		expiresAt: new Date(expiresAt).toISOString(),
		expiresInSeconds: expiresIn,
		hasRefreshToken: !!tokenData.refreshToken,
		message: isExpired
			? 'Tokens expired. Will attempt refresh on next API call, or re-authenticate via Claude Code.'
			: `Tokens valid for ${Math.floor(expiresIn / 60)} minutes`,
	})
})

/**
 * GET /api/accounts - Get all accounts with positions
 */
api.get('/accounts', async (c) => {
	const includePositions = c.req.query('positions') !== 'false'

	return handleApiCall(c, 'getAccounts', async (client) => {
		const accounts = await client.trader.accounts.getAccounts({
			queryParams: includePositions ? { fields: 'positions' } : undefined,
		})
		return accounts
	})
})

/**
 * GET /api/accounts/:accountNumber - Get specific account
 */
api.get('/accounts/:accountNumber', async (c) => {
	const accountNumber = c.req.param('accountNumber')
	const includePositions = c.req.query('positions') !== 'false'

	return handleApiCall(c, 'getAccount', async (client) => {
		const account = await client.trader.accounts.getAccountByNumber({
			pathParams: { accountNumber },
			queryParams: includePositions ? { fields: 'positions' } : undefined,
		})
		return account
	})
})

/**
 * GET /api/quotes - Get quotes for multiple symbols
 */
api.get('/quotes', async (c) => {
	const symbolsParam = c.req.query('symbols')

	if (!symbolsParam) {
		return c.json({ error: 'Missing required parameter: symbols' }, 400)
	}

	// Split comma-separated symbols into array
	const symbols = symbolsParam.split(',').map((s) => s.trim())

	return handleApiCall(c, 'getQuotes', async (client) => {
		const quotes = await client.marketData.quotes.getQuotes({
			queryParams: { symbols },
		})
		return quotes
	})
})

/**
 * GET /api/quotes/:symbol - Get quote for a single symbol
 */
api.get('/quotes/:symbol', async (c) => {
	const symbol = c.req.param('symbol')

	return handleApiCall(c, 'getQuote', async (client) => {
		const quote = await client.marketData.quotes.getQuotes({
			queryParams: { symbols: [symbol] },
		})
		return quote
	})
})

/**
 * GET /api/transactions - Get account transactions
 */
api.get('/transactions', async (c) => {
	const accountNumber = c.req.query('account')
	const startDate = c.req.query('startDate')
	const endDate = c.req.query('endDate')
	const types = c.req.query('types') || 'TRADE'

	if (!accountNumber) {
		return c.json({ error: 'Missing required parameter: account' }, 400)
	}

	return handleApiCall(c, 'getTransactions', async (client) => {
		const transactions = await client.trader.transactions.getTransactions({
			pathParams: { accountNumber },
			queryParams: {
				types: types as any,
				startDate,
				endDate,
			},
		})
		return transactions
	})
})

/**
 * GET /api/orders - Get orders for an account
 */
api.get('/orders', async (c) => {
	const accountNumber = c.req.query('account')
	const status = c.req.query('status')

	// Default to last 60 days if not specified (required params)
	const now = new Date()
	const sixtyDaysAgo = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000)
	const fromEnteredTime =
		c.req.query('fromEnteredTime') || sixtyDaysAgo.toISOString()
	const toEnteredTime = c.req.query('toEnteredTime') || now.toISOString()

	return handleApiCall(c, 'getOrders', async (client) => {
		if (accountNumber) {
			// Get orders for specific account
			const orders = await client.trader.orders.getOrdersByAccount({
				pathParams: { accountNumber },
				queryParams: {
					fromEnteredTime,
					toEnteredTime,
					...(status && { status: status as any }),
				},
			})
			return orders
		} else {
			// Get orders for all accounts
			const orders = await client.trader.orders.getOrders({
				queryParams: {
					fromEnteredTime,
					toEnteredTime,
					...(status && { status: status as any }),
				},
			})
			return orders
		}
	})
})

/**
 * GET /api/pricehistory/:symbol - Get price history for a symbol
 * Query params:
 *   - periodType: day, month, year, ytd
 *   - period: number of periods
 *   - frequencyType: minute, daily, weekly, monthly
 *   - frequency: frequency value (default: 1)
 *   - startDate: start timestamp in milliseconds or ISO date string
 *   - endDate: end timestamp in milliseconds or ISO date string
 */
api.get('/pricehistory/:symbol', async (c) => {
	const symbol = c.req.param('symbol')
	const periodType = c.req.query('periodType')
	const period = c.req.query('period')
	const frequencyType = c.req.query('frequencyType')
	const frequencyParam = c.req.query('frequency')
	const startDateParam = c.req.query('startDate')
	const endDateParam = c.req.query('endDate')

	// Default frequency to 1 (required param)
	const frequency = frequencyParam ? parseInt(frequencyParam) : 1

	// Parse dates - accept timestamps (ms) or ISO date strings
	const parseDate = (val: string | undefined): number | undefined => {
		if (!val) return undefined
		const num = parseInt(val)
		if (!isNaN(num)) return num // Already a timestamp
		const date = new Date(val)
		return isNaN(date.getTime()) ? undefined : date.getTime()
	}

	const startDate = parseDate(startDateParam)
	const endDate = parseDate(endDateParam)

	return handleApiCall(c, 'getPriceHistory', async (client) => {
		const history = await client.marketData.priceHistory.getPriceHistory({
			queryParams: {
				symbol,
				frequency,
				...(periodType && { periodType: periodType as any }),
				...(period && { period: parseInt(period) }),
				...(frequencyType && { frequencyType: frequencyType as any }),
				...(startDate && { startDate }),
				...(endDate && { endDate }),
			},
		})
		return history
	})
})

export { api as ApiHandler }
