import { z } from 'zod'

/**
 * Schema for validating the approved clients cookie content.
 * Ensures the cookie contains an array of string client IDs.
 */
export const ApprovedClientsSchema = z.array(z.string())

/**
 * Schema for OAuth request information
 * Matches the AuthRequest interface from @cloudflare/workers-oauth-provider
 */
const AuthRequestSchema = z.object({
	// Required fields
	responseType: z.string(),
	clientId: z.string(),
	redirectUri: z.string(),
	scope: z.array(z.string()),
	state: z.string(),
	// Optional fields
	codeChallenge: z.string().optional(),
	codeChallengeMethod: z.string().optional(),
})

/**
 * Schema for validating state data.
 * Includes common fields that may be present in the state object.
 */
export const StateSchema = z
	.object({
		clientId: z.string().optional(),
		userId: z.string().optional(),
		oauthReqInfo: AuthRequestSchema.optional(),
	})
	.passthrough()

/**
 * Type for the state data
 */
export type StateData = z.infer<typeof StateSchema>
