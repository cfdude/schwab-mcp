// Export all auth-related modules
export * from './client'
export * from './cookies'
export { SchwabHandler } from './handler'
export * from './tokenStateMachine'
export * from './tokenInterface'
export * from './stateUtils'
import { logger } from '../shared/logger'
import { type ITokenManager } from './tokenInterface'

// Store a reference to the token manager for singleton access
let tokenManagerInstance: ITokenManager | null = null

/**
 * Initialize the token manager singleton that will be used across all components
 *
 * This is the single point of initialization for the token manager. All components
 * that need access to the token manager should use this singleton to ensure
 * consistent token handling throughout the application.
 *
 * @param manager The token manager implementation to use
 */
export function initializeTokenManager(manager: ITokenManager): void {
	logger.info('Initializing central token manager singleton')
	if (tokenManagerInstance) {
		logger.info('Token manager already initialized, updating instance')
	} else {
		logger.info('Initializing central token manager singleton')
	}

	tokenManagerInstance = manager
}
