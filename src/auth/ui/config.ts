/**
 * OAuth Approval Dialog Configuration
 *
 * Configuration for the Cloudflare-style streamlined approval dialog
 */

/**
 * Approval configuration options
 */
export const APPROVAL_CONFIG = {
	/**
	 * Auto-redirect countdown time in seconds
	 */
	COUNTDOWN_SECONDS: 10,

	/**
	 * Show server logo in approval dialog
	 */
	SHOW_LOGO: true,

	/**
	 * Server logo URL (optional - will use clearbit if not provided)
	 */
	LOGO_URL: 'https://logo.clearbit.com/schwab.com',
} as const
