import { type SchwabApiClient } from '@sudowealth/schwab-api'
import { type z } from 'zod'

export interface ToolSpec<S extends z.ZodSchema> {
	name: string
	description: string
	schema: S
	call: (client: SchwabApiClient, params: z.infer<S>) => Promise<unknown>
}
