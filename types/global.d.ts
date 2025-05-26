import { type SchwabApiClient } from '@sudowealth/schwab-api'

declare global {
	// Cached Schwab API client instance for reuse across requests
	var __schwabClient: SchwabApiClient | undefined
}

export {}
