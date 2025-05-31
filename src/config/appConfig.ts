import { z } from 'zod'
import { type Env, type ValidatedEnv } from '../../types/env'
import { logger } from '../shared/logger'

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
})

export function buildConfig(env: Env): ValidatedEnv {
	try {
		const validated = envSchema.parse(env)
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
