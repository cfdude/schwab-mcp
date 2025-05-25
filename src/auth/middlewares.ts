import { type MiddlewareHandler } from 'hono'
import { initializeEnvironment, isEnvironmentInitialized } from '../config'
import { type Env } from '../types/env'

/**
 * Middleware to ensure environment is initialized
 *
 * This middleware checks if the environment has been initialized,
 * and if not, initializes it with the current context's environment.
 *
 * @returns A middleware handler that initializes the environment
 */
export const ensureEnvInitialized: MiddlewareHandler<{
	Bindings: Env
}> = async (c, next) => {
	if (!isEnvironmentInitialized()) {
		initializeEnvironment(c.env)
	}
	await next()
}
