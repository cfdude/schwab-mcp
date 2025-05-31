import { type ValidatedEnv } from '../../types/env'
import { buildConfig } from '../config'
import { makeKvTokenStore } from './kvTokenStore'
import { logger } from './logger'

interface DiagnosticInfo {
	timestamp: string
	hasTokenManager: boolean
	hasClient: boolean
	implementationType: string
	environment?: {
		hasClientId: boolean
		hasClientSecret: boolean
		hasRedirectUri: boolean
		hasCookieKey: boolean
		hasOAuthKV: boolean
	}
	kvTokenStatus?: {
		hasTokenInKV: boolean
		tokenKey: string
		hasAccessToken: boolean
		hasRefreshToken: boolean
		expiresAt?: string
	}
	kvTokenError?: string
	environmentError?: string
	tokenManagerDiagnostics?: any
	tokenManagerReport?: any
	tokenManagerDiagnosticError?: string
	tokenStatus?: {
		hasValidAccessToken: boolean
		hasExpiredAccessToken: boolean
		hasRefreshToken: boolean
		expiresInSeconds?: number
		lastTokenOperation?: string
	}
}

interface DiagnosticContext {
	tokenManager: any
	client: any
	validatedConfig?: ValidatedEnv
	env: any
	props?: {
		schwabUserId?: string
		clientId?: string
	}
}

/**
 * Gathers comprehensive diagnostic information about the OAuth provider state
 * @param context - The diagnostic context containing necessary dependencies
 * @returns Diagnostic information object
 */
export async function gatherDiagnostics(
	context: DiagnosticContext,
): Promise<DiagnosticInfo> {
	logger.info('Gathering diagnostic information')
	const diagnosticInfo: DiagnosticInfo = {
		timestamp: new Date().toISOString(),
		hasTokenManager: !!context.tokenManager,
		hasClient: !!context.client,
		implementationType: context.tokenManager
			? context.tokenManager.constructor.name
			: 'undefined',
	}

	try {
		const env = context.validatedConfig ?? buildConfig(context.env)
		diagnosticInfo.environment = {
			hasClientId: !!env.SCHWAB_CLIENT_ID,
			hasClientSecret: !!env.SCHWAB_CLIENT_SECRET,
			hasRedirectUri: !!env.SCHWAB_REDIRECT_URI,
			hasCookieKey: !!env.COOKIE_ENCRYPTION_KEY,
			hasOAuthKV: !!env.OAUTH_KV,
		}

		// Add KV token diagnostics
		if (env.OAUTH_KV && context.props) {
			const kvToken = makeKvTokenStore(env.OAUTH_KV)
			const tokenIds = {
				schwabUserId: context.props.schwabUserId,
				clientId: context.props.clientId,
			}

			try {
				const kvTokenData = await kvToken.load(tokenIds)
				diagnosticInfo.kvTokenStatus = {
					hasTokenInKV: !!kvTokenData,
					tokenKey: kvToken.kvKey(tokenIds),
					hasAccessToken: !!kvTokenData?.accessToken,
					hasRefreshToken: !!kvTokenData?.refreshToken,
					expiresAt: kvTokenData?.expiresAt
						? new Date(kvTokenData.expiresAt).toISOString()
						: undefined,
				}
			} catch (kvError) {
				diagnosticInfo.kvTokenError =
					kvError instanceof Error ? kvError.message : String(kvError)
			}
		}
	} catch (envError) {
		diagnosticInfo.environmentError =
			envError instanceof Error ? envError.message : String(envError)
	}

	if (context.tokenManager) {
		try {
			// Get diagnostics from EnhancedTokenManager
			if (typeof context.tokenManager.getDiagnostics === 'function') {
				diagnosticInfo.tokenManagerDiagnostics =
					await context.tokenManager.getDiagnostics()

				// Extract high-level token status summary if available
				const diag = diagnosticInfo.tokenManagerDiagnostics
				if (diag && typeof diag === 'object') {
					diagnosticInfo.tokenStatus = {
						hasValidAccessToken: !!(diag.hasAccessToken && diag.expiresIn > 0),
						hasExpiredAccessToken: !!(
							diag.hasAccessToken && diag.expiresIn <= 0
						),
						hasRefreshToken: !!diag.hasRefreshToken,
						expiresInSeconds: diag.expiresIn,
						lastTokenOperation: diag.lastTokenOperation,
					}
				}
			} else if (
				typeof context.tokenManager.generateTokenReport === 'function'
			) {
				diagnosticInfo.tokenManagerReport =
					await context.tokenManager.generateTokenReport()
			}
		} catch (diagError) {
			diagnosticInfo.tokenManagerDiagnosticError =
				diagError instanceof Error ? diagError.message : String(diagError)
		}
	}

	logger.info('Diagnostic information gathered', {
		timestamp: diagnosticInfo.timestamp,
		tokenStatusSummary: diagnosticInfo.tokenStatus
			? `AccessToken: ${diagnosticInfo.tokenStatus.hasValidAccessToken ? 'Valid' : 'Invalid/Expired'}, RefreshToken: ${diagnosticInfo.tokenStatus.hasRefreshToken ? 'Present' : 'Missing'}`
			: 'No token status available',
	})
	return diagnosticInfo
}
