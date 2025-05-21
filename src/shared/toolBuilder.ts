import { type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { type SchwabApiClient } from '@sudowealth/schwab-api'
import { z } from 'zod'
import { type Result } from '../types/result'
import { type FormattedSuccessPayload } from './formatters'
import { logger } from './logger'

// 1. Define and export the toolRegistry
export const toolRegistry = new Map<
	string,
	{
		schema: z.ZodSchema<any, any>
		handler: (
			input: any,
			client: SchwabApiClient,
		) => Promise<ToolResponse | Result<FormattedSuccessPayload<any>> | any>
	}
>()

export type ToolResponse<T = any> =
	| { success: true; data: T; message?: string }
	| { success: false; error: Error; details?: Record<string, any> }

export type McpContentArray = {
	content: Array<{ type: string; text: string }>
	isError?: boolean
}

export function formatResponse(
	response: ToolResponse | Result<any>,
): McpContentArray {
	// Handle ToolResponse format
	if (response && 'success' in response) {
		if (response.success) {
			const dataToLog = 'data' in response ? response.data : null
			const message =
				('message' in response && response.message) ||
				(dataToLog && (dataToLog as any).message) ||
				'Operation successful'
			return {
				content: [
					{ type: 'text', text: message },
					{ type: 'text', text: JSON.stringify(dataToLog, null, 2) },
				],
			}
		} else {
			let errorMessage = 'An error occurred'
			if ('error' in response && response.error) {
				errorMessage =
					response.error instanceof Error
						? response.error.message
						: String(response.error)
			}
			const content = [{ type: 'text', text: errorMessage }]
			if ('details' in response && response.details) {
				if (response.details.formattedDetails) {
					content.push({
						type: 'text',
						text: `Details: ${response.details.formattedDetails}`,
					})
				}
				const diagnosticInfo = {
					status: response.details.status,
					code: response.details.code,
					requestId: response.details.requestId,
				}
				if (Object.values(diagnosticInfo).some((val) => val !== undefined)) {
					content.push({
						type: 'text',
						text: `Diagnostic Info: ${JSON.stringify(diagnosticInfo)}`,
					})
				}
			}
			return { content, isError: true }
		}
	}
	return {
		content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
	}
}

function isSchwabApiError(error: any): boolean {
	return (
		error &&
		typeof error === 'object' &&
		(error.name === 'SchwabApiError' ||
			error.constructor?.name === 'SchwabApiError')
	)
}

function isAuthError(error: any): boolean {
	return (
		error &&
		typeof error === 'object' &&
		(error.name === 'SchwabAuthError' ||
			error.constructor?.name === 'SchwabAuthError')
	)
}

export function toolError(
	message: string | Error | unknown,
	details?: Record<string, any>,
): ToolResponse {
	const error = message instanceof Error ? message : new Error(String(message))
	let enhancedDetails = { ...details }
	if (isSchwabApiError(error) || isAuthError(error)) {
		const apiError = error as any
		enhancedDetails = {
			...enhancedDetails,
			status: apiError.status,
			code: apiError.code,
			parsedError: apiError.parsedError,
		}
		if (typeof apiError.getRequestId === 'function') {
			enhancedDetails.requestId = apiError.getRequestId()
		}
		if (typeof apiError.getFormattedDetails === 'function') {
			enhancedDetails.formattedDetails = apiError.getFormattedDetails()
		}
	}
	logger.error('Tool error', {
		message: error.message, // Log only message to avoid large objects in primary log
		details: enhancedDetails,
		stack: error.stack,
	})
	return { success: false, error, details: enhancedDetails }
}

export function toolSuccess<T>({
	data,
	message,
	source,
}: {
	data: T
	message?: string
	source: string
}): ToolResponse<T> {
	const count = Array.isArray(data) ? data.length : 1
	logger.debug(`Tool success: ${source}`, {
		dataPreview: Array.isArray(data) ? `Array of ${count} items` : typeof data,
		count,
	})
	return { success: true, data, message }
}

export function mergeShapes<T extends z.ZodRawShape[]>(
	...shapes: T
): z.ZodRawShape {
	return shapes.reduce((acc, shape) => ({ ...acc, ...shape }), {})
}

export function createTool<S extends z.ZodSchema<any, any>>(
	client: SchwabApiClient,
	server: McpServer,
	{
		name,
		schema,
		handler,
	}: {
		name: string
		schema: S
		handler: (
			input: z.infer<S>,
			client: SchwabApiClient,
		) => Promise<ToolResponse | Result<FormattedSuccessPayload<any>> | any>
	},
) {
	// Populate the internal toolRegistry
	toolRegistry.set(name, { schema, handler })
	logger.info(`[ToolBuilder] Added tool '${name}' to internal toolRegistry.`)

	// Keep individual tool registration with McpServer for potential direct calls
	// or if the dispatcher logic is ever removed.
	logger.info(
		`[ToolBuilder] Registering tool with McpServer for direct call: '${name}'.`,
	)
	server.tool(
		name,
		schema instanceof z.ZodObject ? schema.shape : {},
		async (args: any) => {
			try {
				logger.info(`[ToolBuilder] Direct invocation of tool: ${name}`)
				let parsedInput: z.infer<S>
				try {
					parsedInput = schema.parse(args)
				} catch (validationError) {
					logger.error(`Input validation error in direct tool: ${name}`, {
						validationError:
							validationError instanceof Error
								? validationError.message
								: String(validationError),
						argsReceived: args,
					})
					return formatResponse(
						toolError('Invalid input for direct tool call.', {
							details:
								validationError instanceof Error
									? validationError.message
									: String(validationError),
						}),
					)
				}
				const result = await handler(parsedInput, client)
				if (result && result.content && Array.isArray(result.content)) {
					return result
				}
				return formatResponse(result)
			} catch (error) {
				logger.error(`Unexpected error in direct tool: ${name}`, {
					error: error instanceof Error ? error.message : String(error),
				})
				return formatResponse(
					toolError(
						error instanceof Error
							? error
							: new Error('Unknown error in direct tool call'),
						{ source: name },
					),
				)
			}
		},
	)
	// The log from `createTool` in the original plan was inside the `createTool` that takes `name, schema, handler`
	// The message "Registered tool with McpServer: '${name}' using schema definition." is a bit redundant now
	// as we have a more specific log above for direct call registration.
	// Let's stick to the specific logs for clarity.
}
