import { logger } from '../shared/logger'
import { type Env, type ValidatedEnv } from '../types/env'

export const REQUIRED_VARS = [
  'SCHWAB_CLIENT_ID',
  'SCHWAB_CLIENT_SECRET',
  'COOKIE_ENCRYPTION_KEY',
  'SCHWAB_REDIRECT_URI',
] as const

export function buildConfig(env: Env): ValidatedEnv {
  const missing: string[] = []
  for (const name of REQUIRED_VARS) {
    const value = (env as any)[name]
    if (!value) missing.push(name)
  }
  if (missing.length > 0) {
    const msg = `Missing required environment variables: ${missing.join(', ')}`
    logger.error(msg)
    throw new Error(msg)
  }

  return Object.freeze({
    SCHWAB_CLIENT_ID: env.SCHWAB_CLIENT_ID,
    SCHWAB_CLIENT_SECRET: env.SCHWAB_CLIENT_SECRET,
    COOKIE_ENCRYPTION_KEY: env.COOKIE_ENCRYPTION_KEY,
    SCHWAB_REDIRECT_URI: env.SCHWAB_REDIRECT_URI,
    OAUTH_KV: env.OAUTH_KV,
    LOG_LEVEL: env.LOG_LEVEL,
  })
}
