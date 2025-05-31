import { z } from 'zod'
import { type Env, type ValidatedEnv } from '../../types/env'
import { logger } from '../shared/logger'
import { validateRedirectPattern } from './redirectAllowlist'

const envSchema = z.object({
	SCHWAB_CLIENT_ID: z
		.string({
			required_error: 'SCHWAB_CLIENT_ID is required for OAuth authentication',
		})
		.min(1, 'SCHWAB_CLIENT_ID cannot be empty'),

	SCHWAB_CLIENT_SECRET: z
		.string({
			required_error:
				'SCHWAB_CLIENT_SECRET is required for OAuth authentication',
		})
		.min(1, 'SCHWAB_CLIENT_SECRET cannot be empty'),

	COOKIE_ENCRYPTION_KEY: z
		.string({
			required_error:
				'COOKIE_ENCRYPTION_KEY is required for secure cookie storage',
		})
		.min(1, 'COOKIE_ENCRYPTION_KEY cannot be empty'),

	SCHWAB_REDIRECT_URI: z
		.string({
			required_error: 'SCHWAB_REDIRECT_URI is required for OAuth callback',
		})
		.url('SCHWAB_REDIRECT_URI must be a valid URL'),

	OAUTH_KV: z.any().refine((v) => !!v, {
		message: 'OAUTH_KV binding is required for token storage',
	}),

	LOG_LEVEL: z
		.enum(['debug', 'info', 'warn', 'error'])
		.optional()
		.default('info'),

	ALLOWED_REDIRECT_REGEXPS: z
		.string()
		.optional()
		.default('')
		.refine(
			(value) => {
				if (!value) return true
				const patterns = value
					.split(',')
					.map((p) => p.trim())
					.filter((p) => p.length > 0)

				try {
					for (const pattern of patterns) {
						validateRedirectPattern(pattern)
					}
					return true
				} catch (error) {
					logger.error(
						'ALLOWED_REDIRECT_REGEXPS contains invalid regex patterns',
						{
							error: error instanceof Error ? error.message : 'Unknown error',
						},
					)
					return false
				}
			},
			{
				message: 'ALLOWED_REDIRECT_REGEXPS contains invalid regex patterns',
			},
		),
})

export function buildConfig(env: Env): ValidatedEnv {
	try {
		const validated = envSchema.parse(env)

		// Additional validation: Test that createRedirectValidator would succeed
		// This ensures fail-fast behavior at config build time
		if (validated.ALLOWED_REDIRECT_REGEXPS) {
			const testPatterns = validated.ALLOWED_REDIRECT_REGEXPS.split(',')
				.map((p) => p.trim())
				.filter((p) => p.length > 0)

			for (const pattern of testPatterns) {
				try {
					validateRedirectPattern(pattern)
				} catch (error) {
					const msg = `Invalid redirect URI pattern in ALLOWED_REDIRECT_REGEXPS: "${pattern}" - ${error instanceof Error ? error.message : 'Unknown error'}`
					logger.error(msg)
					throw new Error(msg)
				}
			}
		}

		return Object.freeze(validated) as ValidatedEnv
	} catch (error) {
		if (error instanceof z.ZodError) {
			const issues = error.issues
				.map((issue) => {
					const path = issue.path.join('.')
					return `  - ${path}: ${issue.message}`
				})
				.join('\n')

			const msg = `Environment validation failed:\n${issues}`
			logger.error(msg)
			throw new Error(msg)
		}
		throw error
	}
}
