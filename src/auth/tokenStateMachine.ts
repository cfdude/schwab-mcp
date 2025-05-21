import {
	type EnhancedTokenManager, // Directly use EnhancedTokenManager type
	TokenPersistenceEvent, // This enum is from EnhancedTokenManager, check its export
	type TokenData as SchwabApiTokenData, // Alias to avoid conflict
} from '@sudowealth/schwab-api'
import { logger } from '../shared/logger'
import { type CodeFlowTokenData, type TokenLifecycleEvent } from './client'
import { type ITokenManager } from './tokenInterface'

// Use CodeFlowTokenData for internal state, map from/to SchwabApiTokenData when interacting with EnhancedTokenManager
type InternalTokenData = CodeFlowTokenData

type TokenState =
	| { status: 'uninitialized'; isInitializing?: boolean }
	| { status: 'valid'; tokenData: InternalTokenData }
	| { status: 'expired'; tokenData: InternalTokenData }
	| { status: 'refreshing'; tokenData: InternalTokenData }
	| { status: 'error'; error: Error }

export type TokenStateEvent = {
	type: 'state-change' | 'refresh-attempt' | 'reconnect-attempt'
	previousState?: string
	newState?: string
	timestamp: number
	success?: boolean
	error?: Error
	metadata?: Record<string, any>
}

export type TokenStateEventListener = (event: TokenStateEvent) => void

interface ValidateTokenResult {
	valid: boolean
	tokenData?: InternalTokenData
	reason?: string
}

export class TokenStateMachine implements ITokenManager {
	private state: TokenState = { status: 'uninitialized' }
	private tokenClient: EnhancedTokenManager
	// Event handlers mapping for persistence events
	private persistenceEventHandlers: ((
		event: TokenPersistenceEvent,
		data: InternalTokenData | null,
		metadata?: Record<string, any>,
	) => void)[] = []
	private lastReconnectTime = 0
	private stateEventListeners: TokenStateEventListener[] = []
	// refreshRetryCount and maxRefreshRetries are handled by EnhancedTokenManager

	private transitionToUninitialized(isInitializing: boolean = false): void {
		const previousState = this.state.status
		this.state = { status: 'uninitialized', isInitializing }
		const stateDescription = isInitializing ? 'initializing' : 'uninitialized'
		logger.info(`Token state: ${stateDescription}`)
		this.emitStateEvent({
			type: 'state-change',
			previousState,
			newState: 'uninitialized',
			timestamp: Date.now(),
			metadata: { isInitializing },
		})
	}

	private transitionToValid(tokenData: InternalTokenData): void {
		const previousState = this.state.status
		this.state = { status: 'valid', tokenData }
		logger.info('Token state: valid', {
			expiresIn: Math.floor((tokenData.expiresAt - Date.now()) / 1000),
		})
		this.emitStateEvent({
			type: 'state-change',
			previousState,
			newState: 'valid',
			timestamp: Date.now(),
			metadata: {
				expiresAt: tokenData.expiresAt,
				expiresIn: Math.floor((tokenData.expiresAt - Date.now()) / 1000),
			},
		})
	}

	private transitionToExpired(tokenData: InternalTokenData): void {
		const previousState = this.state.status
		this.state = { status: 'expired', tokenData }
		logger.info('Token state: expired')
		this.emitStateEvent({
			type: 'state-change',
			previousState,
			newState: 'expired',
			timestamp: Date.now(),
			metadata: {
				expiresAt: tokenData.expiresAt,
				expiresIn: Math.floor((tokenData.expiresAt - Date.now()) / 1000),
			},
		})
	}

	private transitionToRefreshing(tokenData: InternalTokenData): void {
		const previousState = this.state.status
		this.state = { status: 'refreshing', tokenData }
		logger.info('Token state: refreshing')
		this.emitStateEvent({
			type: 'state-change',
			previousState,
			newState: 'refreshing',
			timestamp: Date.now(),
			metadata: {
				expiresAt: tokenData.expiresAt,
				expiresIn: Math.floor((tokenData.expiresAt - Date.now()) / 1000),
			},
		})
	}

	private transitionToError(error: Error): void {
		const previousState = this.state.status
		this.state = { status: 'error', error }
		logger.error('Token state: error', { errorMessage: error.message })
		this.emitStateEvent({
			type: 'state-change',
			previousState,
			newState: 'error',
			timestamp: Date.now(),
			error,
		})
	}

	private emitStateEvent(event: TokenStateEvent): void {
		if (!event.timestamp) event.timestamp = Date.now()
		for (const listener of this.stateEventListeners) {
			try {
				listener(event)
			} catch (error) {
				logger.error('Error in token state event listener', {
					error: error instanceof Error ? error.message : String(error),
				})
			}
		}
	}

	public onStateEvent(listener: TokenStateEventListener): void {
		this.stateEventListeners.push(listener)
	}

	public offStateEvent(listener: TokenStateEventListener): void {
		this.stateEventListeners = this.stateEventListeners.filter(
			(l) => l !== listener,
		)
	}

	constructor(tokenClient: EnhancedTokenManager) {
		this.tokenClient = tokenClient

		logger.info('Setting up custom persistence event handling')
		// Add a custom persistence event handler since onPersistenceEvent is not available
		// This is a custom implementation that will be called by other methods
		this.addPersistenceEventHandler(
			(
				event: TokenPersistenceEvent,
				data: InternalTokenData | null,
				metadata?: Record<string, any>,
			) => {
				let lifecycleEventType: TokenLifecycleEvent['type'] | null = null
				let isError = false
				const errorFromMetadata = metadata?.error
					? new Error(String(metadata.error))
					: undefined

				switch (event) {
					case TokenPersistenceEvent.TOKEN_LOADED:
						lifecycleEventType = 'load'
						logger.info('Persistence Event: Token Loaded', { data, metadata })
						break
					case TokenPersistenceEvent.TOKEN_SAVED:
						if (metadata?.operation === 'refresh') {
							lifecycleEventType = 'refresh'
							logger.info('Persistence Event: Token Saved (after refresh)', {
								data,
								metadata,
							})
						} else if (metadata?.operation === 'code_exchange') {
							// Successfully exchanged code and saved tokens
							lifecycleEventType = 'load' // Or a more specific 'exchanged_and_loaded' if you add it
							logger.info(
								'Persistence Event: Token Saved (after code exchange)',
								{ data, metadata },
							)
						} else {
							lifecycleEventType = 'save' // Generic save
							logger.info('Persistence Event: Token Saved (generic)', {
								data,
								metadata,
							})
						}
						break
					case TokenPersistenceEvent.TOKEN_LOAD_FAILED:
						lifecycleEventType = 'error'
						isError = true
						logger.error('Persistence Event: Token Load Failed', {
							data,
							metadata,
						})
						break
					case TokenPersistenceEvent.TOKEN_SAVE_FAILED:
						lifecycleEventType = 'error'
						isError = true
						logger.error('Persistence Event: Token Save Failed', {
							data,
							metadata,
							operation: metadata?.operation,
						})
						break
					case TokenPersistenceEvent.TOKEN_VALIDATION_FAILED:
						lifecycleEventType = 'error'
						isError = true
						logger.warn('Persistence Event: Token Validation Failed', {
							data,
							metadata,
						})
						break
					case TokenPersistenceEvent.TOKEN_VALIDATED:
						// For TOKEN_VALIDATED, check if we're in the middle of a refresh
						if (this.state.status === 'refreshing') {
							lifecycleEventType = 'refresh'
							logger.info(
								'Persistence Event: Token Validated (during refresh)',
								{
									data,
									metadata,
								},
							)
						} else {
							// Just an informational event in most cases
							logger.info('Persistence Event: Token Validated', {
								data,
								metadata,
							})
							// No state change needed for most validation events
							// lifecycleEventType remains null
						}
						break
				}

				if (lifecycleEventType) {
					this.handleTokenEvent({
						type: lifecycleEventType,
						tokenData: data, // data is TokenData from EnhancedTokenManager
						error: isError
							? errorFromMetadata || new Error(`Persistence event: ${event}`)
							: undefined,
						timestamp: Date.now(),
					})
				}
			},
		)

		// Set up logging of state events
		this.onStateEvent((event) => {
			if (event.type === 'state-change') {
				logger.info(
					`Token state transition: ${event.previousState} -> ${event.newState}`,
				)
			} else {
				logger.debug(`Token event: ${event.type}`, {
					success: event.success,
					metadata: event.metadata,
				})
			}
		})
	}

	/**
	 * Handles token lifecycle events from the token client or internal transitions
	 */
	private handleTokenEvent(event: TokenLifecycleEvent): void {
		logger.info(`TokenStateMachine handling lifecycle event: ${event.type}`)
		switch (event.type) {
			case 'load':
			case 'refresh': // Treat refresh success similarly to a successful load
				if (event.tokenData) {
					const validationResult = this.validateTokenData(event.tokenData)
					if (validationResult.valid && validationResult.tokenData) {
						const validTokenData = validationResult.tokenData
						if (this.isTokenDataExpired(validTokenData)) {
							logger.info(
								`Loaded/Refreshed token is expired, transitioning to expired state.`,
							)
							this.transitionToExpired(validTokenData)
						} else {
							logger.info(`Loaded/Refreshed token is valid.`)
							this.transitionToValid(validTokenData)
						}
					} else {
						logger.warn(
							`Token ${event.type} event: validation failed: ${validationResult.reason}`,
						)
						this.transitionToError(
							new Error(
								validationResult.reason ||
									`Token validation failed during ${event.type}`,
							),
						)
					}
				} else {
					logger.warn(`Token ${event.type} event: no tokenData provided.`)
					this.transitionToError(
						new Error(`No tokenData in ${event.type} event`),
					)
				}
				break
			case 'expire': // This event might be triggered externally or by a timer
				if (this.state.status === 'valid' && 'tokenData' in this.state) {
					logger.info('Token expire event received, transitioning to expired.')
					this.transitionToExpired(this.state.tokenData)
				}
				break
			case 'error':
				if (event.error) {
					logger.warn('Token error event received', {
						errorMessage: event.error.message,
					})
					this.transitionToError(event.error)
				} else {
					logger.warn(
						'Token error event received without specific error object.',
					)
					this.transitionToError(new Error('Unknown token error event'))
				}
				break
		}
	}

	/**
	 * Validates that token data meets requirements and provides detailed feedback
	 * Leverages EnhancedTokenManager's validation when available
	 */
	private validateTokenData(
		tokenData: SchwabApiTokenData | InternalTokenData | null,
	): ValidateTokenResult {
		if (!tokenData) {
			return { valid: false, reason: 'Token data is null or undefined' }
		}

		// Ensure our specific required fields are present and correctly typed
		if (!tokenData.accessToken || typeof tokenData.accessToken !== 'string') {
			return { valid: false, reason: 'Missing or invalid accessToken' }
		}
		if (!tokenData.refreshToken || typeof tokenData.refreshToken !== 'string') {
			// Allow empty refresh token if ETM considers it valid, but log.
			if (tokenData.refreshToken !== '') {
				logger.warn(
					"Refresh token is present but not a non-empty string. This might be acceptable depending on ETM's logic.",
				)
			}
		}
		if (typeof tokenData.expiresAt !== 'number' || tokenData.expiresAt <= 0) {
			return { valid: false, reason: 'Missing or invalid expiresAt' }
		}

		return {
			valid: true,
			tokenData: {
				// Ensure it's mapped to InternalTokenData
				accessToken: tokenData.accessToken,
				refreshToken: tokenData.refreshToken || '',
				expiresAt: tokenData.expiresAt,
			},
		}
	}

	/**
	 * Checks if a token is expired or will expire soon
	 * Uses EnhancedTokenManager's isAccessTokenNearingExpiration
	 */
	private isTokenExpired(tokenData: InternalTokenData): boolean {
		// Default refresh threshold: 5 minutes (300000ms)
		const refreshThresholdMs = 300000

		try {
			// Custom implementation since isAccessTokenNearingExpiration is not available
			return this.isAccessTokenNearingExpiration(
				tokenData.expiresAt,
				refreshThresholdMs,
			)
		} catch (error) {
			// If enhanced check fails, fall back to basic check
			logger.warn('Enhanced token expiration check failed', { error })

			// Basic check (fallback)
			return !!(
				tokenData.expiresAt &&
				Date.now() + refreshThresholdMs >= tokenData.expiresAt
			)
		}
	}

	public updateTokenClient(tokenClient: EnhancedTokenManager): void {
		logger.info('Updating token client in TokenStateMachine')
		this.tokenClient = tokenClient
		// Note: Re-subscribing to events or re-passing the event handler would need to happen here
		// if the onTokenEvent mechanism for ETM was used via its constructor.
		// For now, this just updates the client instance.
	}

	public async initialize(): Promise<boolean> {
		if (
			this.state.status !== 'uninitialized' &&
			this.state.status !== 'error'
		) {
			logger.info(`Initialization skipped, current state: ${this.state.status}`)
			return this.state.status === 'valid'
		}
		if (this.state.status === 'uninitialized' && this.state.isInitializing) {
			logger.info('Initialization already in progress')
			return false // Or await a promise representing the ongoing initialization
		}
		this.transitionToUninitialized(true)
		try {
			logger.debug(
				'TokenStateMachine: Calling ETM.getTokenData() for initialization.',
			)
			const etmTokenData = await this.tokenClient.getTokenData()
			const validationResult = this.validateTokenData(etmTokenData)

			if (!validationResult.valid || !validationResult.tokenData) {
				logger.info(
					`Initialization: No valid token data from ETM: ${validationResult.reason || 'unknown'}`,
				)
				this.transitionToUninitialized(false)
				return false
			}
			const internalTokenData = validationResult.tokenData
			if (this.isTokenDataExpired(internalTokenData)) {
				logger.info('Initialization: Token is expired, attempting refresh.')
				this.transitionToExpired(internalTokenData)
				return await this.refresh()
			}
			logger.info('Initialization: Token is valid.')
			this.transitionToValid(internalTokenData)
			return true
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			logger.error('Error initializing token state', { error: message })
			this.transitionToError(
				error instanceof Error ? error : new Error(message),
			)
			return false
		}
	}

	public async getAccessToken(): Promise<string | null> {
		logger.debug(`getAccessToken called. Current state: ${this.state.status}`)
		if (
			this.state.status === 'valid' &&
			'tokenData' in this.state &&
			this.state.tokenData
		) {
			// Before returning, quickly check if it's now expired according to our definition
			if (this.isTokenDataExpired(this.state.tokenData)) {
				logger.info(
					'Token was valid, but now considered expired. Attempting refresh via ensureValidToken.',
				)
				await this.ensureValidToken() // This will trigger refresh if needed
				// After ensureValidToken, re-check state
				if (
					this.state.status === 'valid' &&
					'tokenData' in this.state &&
					this.state.tokenData
				) {
					return this.state.tokenData.accessToken
				} else {
					logger.warn(
						'Token still not valid after ensureValidToken in getAccessToken flow.',
					)
					return null
				}
			}
			return this.state.tokenData.accessToken
		}

		const isValidOrCanBeMadeValid = await this.ensureValidToken()
		if (!isValidOrCanBeMadeValid) {
			logger.warn('getAccessToken: ensureValidToken returned false.')
			return null
		}
		// After ensureValidToken, state should be 'valid' if successful
		if (
			this.state.status === 'valid' &&
			'tokenData' in this.state &&
			this.state.tokenData
		) {
			return this.state.tokenData.accessToken
		}
		// Fallback if state is somehow not 'valid' after a successful ensureValidToken
		logger.warn(
			`getAccessToken: State is ${this.state.status} after successful ensureValidToken. Attempting direct ETM call.`,
		)
		try {
			const tokenFromETM = await this.tokenClient.getAccessToken()
			if (tokenFromETM) {
				// Force update our internal state if ETM provides a token
				const currentTokenDataFromClient = await this.tokenClient.getTokenData()
				if (currentTokenDataFromClient) {
					const validation = this.validateTokenData(currentTokenDataFromClient)
					if (validation.valid && validation.tokenData) {
						this.transitionToValid(validation.tokenData)
					}
				}
			}
			return tokenFromETM
		} catch (etmError) {
			const message =
				etmError instanceof Error ? etmError.message : String(etmError)
			logger.error(
				'getAccessToken: Error from ETM.getAccessToken() fallback.',
				{ error: message },
			)
			this.transitionToError(
				etmError instanceof Error ? etmError : new Error(message),
			)
			return null
		}
	}

	public async ensureValidToken(): Promise<boolean> {
		logger.debug(`ensureValidToken called. Current state: ${this.state.status}`)
		switch (this.state.status) {
			case 'uninitialized':
				if (this.state.isInitializing) {
					logger.info('ensureValidToken: Initialization in progress.')
					return false // Or await a promise
				}
				return await this.initialize()
			case 'valid':
				if (
					'tokenData' in this.state &&
					this.isTokenDataExpired(this.state.tokenData)
				) {
					logger.info(
						'ensureValidToken: Token in valid state but expired, refreshing.',
					)
					this.transitionToExpired(this.state.tokenData)
					return await this.refresh()
				}
				return true
			case 'expired':
				logger.info('ensureValidToken: Token in expired state, refreshing.')
				return await this.refresh()
			case 'error':
				logger.warn(
					'ensureValidToken: Token in error state, attempting re-initialization.',
				)
				return await this.initialize()
			case 'refreshing':
				logger.info('ensureValidToken: Refresh already in progress.')
				// This should ideally await the ongoing refresh promise if one exists
				return false // For now, indicate not yet valid
			default:
				const unknownState = this.state as { status: string }
				logger.error(
					`Unhandled token state in ensureValidToken: ${unknownState.status}`,
				)
				return false
		}
	}

	public async refresh(): Promise<boolean> {
		if (!(this.state.status === 'expired' || this.state.status === 'valid')) {
			logger.warn(
				`Refresh called from invalid state: ${this.state.status}. Attempting ensureValidToken first.`,
			)
			// Try to get to a refreshable state
			const canProceed = await this.ensureValidToken()
			if (
				!canProceed ||
				!(['expired', 'valid'] as string[]).includes(this.state.status)
			) {
				logger.error(
					`Refresh: Could not reach a refreshable state. Current state: ${this.state.status}`,
				)
				return false
			}
		}
		if (!('tokenData' in this.state) || !this.state.tokenData) {
			logger.error(
				'Refresh: No tokenData available in current state to transition to refreshing.',
			)
			return await this.initialize() // Try to recover
		}

		const currentTokenData = this.state.tokenData
		this.transitionToRefreshing(currentTokenData)
		this.emitStateEvent({
			type: 'refresh-attempt',
			timestamp: Date.now(),
			newState: this.state.status,
			metadata: { method: 'ETM.refreshIfNeeded' },
		})

		try {
			logger.debug(
				'TokenStateMachine: Calling ETM.refreshIfNeeded({ force: true })',
			)
			const refreshedSchwabTokenData = await this.tokenClient.refreshIfNeeded({
				force: true,
			})
			// ETM's refreshIfNeeded returns SchwabApiTokenData
			const validationResult = this.validateTokenData(refreshedSchwabTokenData)

			if (validationResult.valid && validationResult.tokenData) {
				logger.info('Refresh successful, token is valid.')
				this.transitionToValid(validationResult.tokenData)
				this.emitStateEvent({
					type: 'refresh-attempt',
					timestamp: Date.now(),
					success: true,
					metadata: { method: 'ETM.refreshIfNeeded', hasTokenData: true },
				})
				return true
			} else {
				const reason =
					validationResult.reason || 'Invalid token data after ETM refresh'
				logger.error(`Refresh failed: ${reason}`)
				this.transitionToError(new Error(reason))
				this.emitStateEvent({
					type: 'refresh-attempt',
					timestamp: Date.now(),
					success: false,
					error: new Error(reason),
					metadata: { method: 'ETM.refreshIfNeeded', validationFailed: true },
				})
				return false
			}
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			logger.error('Error during ETM token refresh operation', {
				error: message,
			})
			this.transitionToError(
				error instanceof Error ? error : new Error(message),
			)
			this.emitStateEvent({
				type: 'refresh-attempt',
				timestamp: Date.now(),
				success: false,
				error: error instanceof Error ? error : new Error(message),
				metadata: { error: true },
			})
			return false
		}
	}

	private readonly MIN_RECONNECT_INTERVAL_MS = 5000
	public async handleReconnection(): Promise<boolean> {
		const now = Date.now()
		if (now - this.lastReconnectTime < this.MIN_RECONNECT_INTERVAL_MS) {
			logger.info('Skipping reconnection, too soon after last attempt.')
			return false // Indicate that reconnection was skipped
		}
		this.lastReconnectTime = now
		logger.info('TokenStateMachine: Handling reconnection.')
		this.emitStateEvent({
			type: 'reconnect-attempt',
			timestamp: Date.now(),
			newState: this.state.status,
		})

		try {
			logger.info('TokenStateMachine: Calling ETM.reconnect()')
			// Assuming EnhancedTokenManager has a reconnect method that attempts to restore a valid session
			await this.tokenClient.triggerReconnection() // Or a more specific reconnect method if available

			// After ETM's reconnect attempt, re-evaluate token state
			logger.info(
				'TokenStateMachine: ETM reconnection attempt finished. Re-initializing state.',
			)
			return await this.initialize() // Re-initialize to fetch and validate the current token state
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			logger.error('Error during ETM reconnection handling', { error: message })
			this.transitionToError(
				error instanceof Error ? error : new Error(message),
			)
			this.emitStateEvent({
				type: 'reconnect-attempt',
				timestamp: Date.now(),
				success: false,
				error: error instanceof Error ? error : new Error(message),
				metadata: { error: true },
			})
			return false
		}
	}

	public async getDiagnostics() {
		const basicDiagnostics = {
			stateMachineStatus: this.state.status,
			isInitializing: (this.state as any).isInitializing || false,
			hasInternalTokenData: 'tokenData' in this.state && !!this.state.tokenData,
			internalTokenExpiresInSec:
				'tokenData' in this.state && this.state.tokenData?.expiresAt
					? Math.floor((this.state.tokenData.expiresAt - Date.now()) / 1000)
					: undefined,
			lastReconnectAttemptMs: this.lastReconnectTime,
		}
		try {
			const etmDiagnostics = await this.tokenClient.getDiagnostics()
			return { ...basicDiagnostics, enhancedTokenManager: etmDiagnostics }
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error)
			logger.warn('Error getting EnhancedTokenManager diagnostics', {
				error: message,
			})
			return { ...basicDiagnostics, enhancedTokenManagerError: message }
		}
	}

	/**
	 * Custom implementation of validateToken for EnhancedTokenManager
	 */
	private customValidateToken(tokenData: InternalTokenData | null): {
		valid: boolean
		reason?: string
	} {
		// Basic validation logic
		if (!tokenData) {
			return { valid: false, reason: 'Token data is null or undefined' }
		}

		// Check for required fields with non-null assertion since we've validated tokenData is not null
		const missingFields = []
		if (!tokenData!.accessToken) missingFields.push('accessToken')
		if (!tokenData!.refreshToken) missingFields.push('refreshToken')
		if (!tokenData!.expiresAt) missingFields.push('expiresAt')

		if (missingFields.length > 0) {
			return {
				valid: false,
				reason: `Token data missing required fields: ${missingFields.join(', ')}`,
			}
		}

		return { valid: true }
	}

	/**
	 * Custom implementation for isAccessTokenNearingExpiration
	 */
	private isAccessTokenNearingExpiration(
		expiresAt: number | undefined,
		thresholdMs: number,
	): boolean {
		if (!expiresAt) return true
		return Date.now() + thresholdMs >= expiresAt
	}

	/**
	 * Custom implementation for reconnect
	 */
	private async customReconnect(): Promise<boolean> {
		try {
			// Try to load tokens from storage
			const apiTokenData = await this.tokenClient.getTokenData()
			if (!apiTokenData) return false

			// Convert to our internal token format
			const tokenData = this.validateTokenData(apiTokenData)
			if (!tokenData.valid) return false

			// If token is expired, try to refresh
			if (
				this.isAccessTokenNearingExpiration(tokenData.tokenData?.expiresAt, 0)
			) {
				try {
					await this.tokenClient.refreshIfNeeded({ force: true })
					return true
				} catch (error) {
					logger.error('Error refreshing token during reconnect', { error })
					return false
				}
			}

			// Token loaded and is valid
			return true
		} catch (error) {
			logger.error('Error during reconnect operation', { error })
			return false
		}
	}

	/**
	 * Add a persistence event handler
	 */
	private addPersistenceEventHandler(
		handler: (
			event: TokenPersistenceEvent,
			data: InternalTokenData | null,
			metadata?: Record<string, any>,
		) => void,
	): void {
		this.persistenceEventHandlers.push(handler)
	}

	/**
	 * Dispatch persistence events to all registered handlers
	 */
	private dispatchPersistenceEvent(
		event: TokenPersistenceEvent,
		data: InternalTokenData | null,
		metadata?: Record<string, any>,
	): void {
		for (const handler of this.persistenceEventHandlers) {
			try {
				handler(event, data, metadata)
			} catch (error) {
				logger.error('Error in persistence event handler', { error })
			}
		}
	}

	private isTokenDataExpired(tokenData: InternalTokenData): boolean {
		const refreshThresholdMs = 300000 // 5 minutes
		const now = Date.now()
		return tokenData.expiresAt - now <= refreshThresholdMs
	}
}
