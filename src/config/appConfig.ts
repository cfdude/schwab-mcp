import { logger } from '../shared/logger'
import { type Env, type ValidatedEnv } from '../types/env'

/**
 * AppConfig - Unified environment configuration provider
 *
 * This class centralizes environment validation and provides type-safe
 * access to environment variables. It uses a singleton pattern to ensure
 * environment is validated only once.
 */
export class AppConfig {
	private static instance: AppConfig | null = null
	private _env: Env | null = null
	private _config: ValidatedEnv | null = null
	private _initialized = false

	private constructor() {}

	/**
	 * Get the singleton instance
	 */
	private static getInstance(): AppConfig {
		if (!AppConfig.instance) {
			AppConfig.instance = new AppConfig()
		}
		return AppConfig.instance
	}

	/**
	 * Validate that a required environment variable exists and is not empty
	 *
	 * @param variableName The name of the environment variable
	 * @param value The value of the environment variable
	 * @throws Error if the environment variable is missing or empty
	 */
	private validateRequiredVariable(
		variableName: string,
		value: string | undefined,
	): string {
		if (!value) {
			const errorMessage = `Required environment variable ${variableName} is missing or empty`
			logger.error(errorMessage)
			throw new Error(errorMessage)
		}
		return value
	}

	/**
	 * Validate all required environment variables and build a validated config
	 *
	 * @throws Error if any required variable is missing
	 * @returns Validated environment configuration
	 */
	private validateEnvironment(): ValidatedEnv {
		if (!this._env) {
			throw new Error(
				'Environment not initialized. Call initialize(env) first.',
			)
		}

		// Define required variables
		const requiredVars = [
			{ name: 'SCHWAB_CLIENT_ID', value: this._env.SCHWAB_CLIENT_ID },
			{ name: 'SCHWAB_CLIENT_SECRET', value: this._env.SCHWAB_CLIENT_SECRET },
			{ name: 'COOKIE_ENCRYPTION_KEY', value: this._env.COOKIE_ENCRYPTION_KEY },
			{ name: 'SCHWAB_REDIRECT_URI', value: this._env.SCHWAB_REDIRECT_URI },
		]

		// Validate all required variables at once to throw a comprehensive error
		const missingVars: string[] = []

		for (const v of requiredVars) {
			if (!v.value) {
				missingVars.push(v.name)
				logger.error(`Missing required environment variable: ${v.name}`)
			}
		}

		if (missingVars.length > 0) {
			const errorMessage = `Missing required environment variables: ${missingVars.join(', ')}`
			logger.error(errorMessage)
			throw new Error(errorMessage)
		}

		// Create validated config with validated values
		const config: ValidatedEnv = {
			SCHWAB_CLIENT_ID: this.validateRequiredVariable(
				'SCHWAB_CLIENT_ID',
				this._env.SCHWAB_CLIENT_ID,
			),
			SCHWAB_CLIENT_SECRET: this.validateRequiredVariable(
				'SCHWAB_CLIENT_SECRET',
				this._env.SCHWAB_CLIENT_SECRET,
			),
			COOKIE_ENCRYPTION_KEY: this.validateRequiredVariable(
				'COOKIE_ENCRYPTION_KEY',
				this._env.COOKIE_ENCRYPTION_KEY,
			),
			SCHWAB_REDIRECT_URI: this.validateRequiredVariable(
				'SCHWAB_REDIRECT_URI',
				this._env.SCHWAB_REDIRECT_URI,
			),
			OAUTH_KV: this._env.OAUTH_KV,
		}

		return config
	}

	/**
	 * Initialize the environment configuration
	 *
	 * @param env The raw environment variables
	 * @returns The validated environment configuration
	 */
	public static initialize(env: Env): ValidatedEnv {
		const instance = this.getInstance()

		if (instance._initialized && instance._config) {
			logger.info('Environment already initialized, using cached config')
			return instance._config
		}

		logger.info('Initializing environment configuration')

		// Store the raw environment
		instance._env = env

		// Validate and create the config
		const config = instance.validateEnvironment()

		// Store the validated config
		instance._config = config
		instance._initialized = true

		logger.info('Environment initialization successful')

		return config
	}

	/**
	 * Get the validated environment configuration
	 *
	 * @throws Error if environment has not been initialized
	 * @returns The validated environment configuration
	 */
	public static getConfig(): ValidatedEnv {
		const instance = this.getInstance()

		if (!instance._initialized || !instance._config) {
			const error = 'Environment not initialized. Call initialize(env) first.'
			logger.error(error)
			throw new Error(error)
		}

		return instance._config
	}

	/**
	 * Check if the environment has been initialized
	 */
	public static isInitialized(): boolean {
		return !!this.getInstance()._initialized
	}

	/**
	 * Gets the Schwab client ID
	 * @throws Error if not initialized
	 */
	public static get SCHWAB_CLIENT_ID(): string {
		return this.getConfig().SCHWAB_CLIENT_ID
	}

	/**
	 * Gets the Schwab client secret
	 * @throws Error if not initialized
	 */
	public static get SCHWAB_CLIENT_SECRET(): string {
		return this.getConfig().SCHWAB_CLIENT_SECRET
	}

	/**
	 * Gets the cookie encryption key
	 * @throws Error if not initialized
	 */
	public static get COOKIE_ENCRYPTION_KEY(): string {
		return this.getConfig().COOKIE_ENCRYPTION_KEY
	}

	/**
	 * Gets the OAuth KV namespace
	 * Note: This is optional
	 * @throws Error if not initialized
	 */
	public static get OAUTH_KV(): KVNamespace | undefined {
		return this.getConfig().OAUTH_KV
	}

	/**
	 * Gets the Schwab redirect URI
	 * @throws Error if not initialized
	 */
	public static get SCHWAB_REDIRECT_URI(): string {
		return this.getConfig().SCHWAB_REDIRECT_URI
	}

	/**
	 * Get diagnostic information about the environment configuration
	 * Useful for troubleshooting
	 */
	public static getDiagnostics(): Record<string, any> {
		const instance = this.getInstance()

		if (!instance._initialized) {
			return {
				initialized: false,
				error: 'Environment not initialized',
			}
		}

		// Base diagnostics object
		const diagnostics: Record<string, any> = {
			initialized: true,
			missingVars: [],
		}

		// Check required variables
		const requiredVars = [
			{ name: 'SCHWAB_CLIENT_ID', accessor: () => this.SCHWAB_CLIENT_ID },
			{
				name: 'SCHWAB_CLIENT_SECRET',
				accessor: () => this.SCHWAB_CLIENT_SECRET,
			},
			{
				name: 'COOKIE_ENCRYPTION_KEY',
				accessor: () => this.COOKIE_ENCRYPTION_KEY,
			},
			{ name: 'SCHWAB_REDIRECT_URI', accessor: () => this.SCHWAB_REDIRECT_URI },
		]

		// Check each variable
		for (const v of requiredVars) {
			try {
				const value = v.accessor()
				diagnostics[`has${v.name}`] = !!value
			} catch (e) {
				diagnostics[`has${v.name}`] = false
				diagnostics.missingVars.push(v.name)
				logger.error(`Missing required environment variable: ${v.name}: ${e}`)
			}
		}

		// Check optional variables
		diagnostics.hasOAUTH_KV = !!instance._config?.OAUTH_KV

		return diagnostics
	}

	/**
	 * Reset the environment (mainly for testing)
	 */
	public static reset(): void {
		const instance = this.getInstance()
		instance._initialized = false
		instance._env = null
		instance._config = null
	}
}

/**
 * Initialize the environment with the provided raw environment variables
 * This should be called once early in the application lifecycle
 *
 * @param env The raw environment variables
 * @returns Validated environment configuration
 */
export function initializeEnvironment(env: Env): ValidatedEnv {
	return AppConfig.initialize(env)
}

/**
 * Get the validated environment configuration
 * This can be called from anywhere in the application
 *
 * @throws Error if environment has not been initialized
 * @returns The validated environment configuration
 */
export function getEnvironment(): ValidatedEnv {
	return AppConfig.getConfig()
}

/**
 * Check if the environment has been initialized
 */
export function isEnvironmentInitialized(): boolean {
	return AppConfig.isInitialized()
}
