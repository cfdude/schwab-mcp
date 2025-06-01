import { type ClientInfo } from '@cloudflare/workers-oauth-provider'
import { type ValidatedEnv } from '../../../types/env'
import { logger } from '../../shared/log'
import { createRedirectValidator } from '../redirectValidator'
import { createApprovalDialogHTML } from './templates'

/**
 * Configuration for the approval dialog
 */
interface ApprovalDialogOptions {
	/**
	 * Client information to display in the approval dialog
	 */
	client: ClientInfo | null
	/**
	 * Server information to display in the approval dialog
	 */
	server: {
		name: string
		logo?: string
		description?: string
	}
	/**
	 * Arbitrary state data to pass through the approval flow
	 * Will be encoded in the form and returned when approval is complete
	 */
	state: Record<string, any>
	/**
	 * Validated environment configuration for redirect validation
	 */
	config: ValidatedEnv
}

/**
 * Sanitizes HTML content to prevent XSS attacks
 * @param unsafe - The unsafe string that might contain HTML
 * @returns A safe string with HTML special characters escaped
 */
export function sanitizeHtml(unsafe: string): string {
	return unsafe
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#039;')
}

/**
 * Renders an approval dialog for OAuth authorization
 * The dialog displays information about the client and server
 * and includes a form to submit approval
 *
 * @param request - The HTTP request
 * @param options - Configuration for the approval dialog
 * @returns A Response containing the HTML approval dialog
 */
export function renderApprovalDialog(
	request: Request,
	options: ApprovalDialogOptions,
): Response {
	const { client, server, state, config } = options

	// Encode state for form submission
	const encodedState = btoa(JSON.stringify(state))

	// Get and validate redirect URIs
	let redirectUris: string[] = []
	let warnAboutUntrustedClient = false
	if (client?.redirectUris && client.redirectUris.length > 0) {
		// Create validator with environment-configurable patterns
		const redirectValidator = createRedirectValidator(config)

		// Validate each redirect URI against the allowlist
		const validUris = redirectValidator.filterValidRedirectUris(
			client.redirectUris,
		)

		if (validUris.length !== client.redirectUris.length) {
			warnAboutUntrustedClient = true
			logger.warn(
				`Client ${client?.clientName || 'Unknown'} has invalid redirect URIs. Valid: ${validUris.length}/${client.redirectUris.length}`,
			)
		}

		redirectUris = validUris
	}

	// Use the template to generate HTML
	const htmlContent = createApprovalDialogHTML({
		client: {
			clientId: client?.clientId || 'unknown',
			name: client?.clientName || 'Unknown MCP Client',
			website: client?.clientUri,
			logoUri: client?.logoUri,
			policyUri: client?.policyUri,
			tosUri: client?.tosUri,
			redirectUris,
			contacts: client?.contacts,
		},
		server: {
			name: server.name,
			logoUri: server.logo,
			description: server.description,
		},
		encodedState,
		warnAboutUntrustedClient,
		formActionPath: new URL(request.url).pathname,
	})

	return new Response(htmlContent, {
		headers: {
			'Content-Type': 'text/html; charset=utf-8',
			'Content-Security-Policy': "default-src 'self'; img-src https: data:;",
		},
	})
}
