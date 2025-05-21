# Shared Utilities

This directory contains shared utilities used throughout the Schwab MCP
implementation.

## Tool Building

The `toolBuilder.ts` module provides a unified approach to building and
registering tools with the MCP server. This ensures consistent token validation,
input validation, error handling, and response formatting across all tools.

### Key Components

- `createTool`: The main factory function for creating and registering tools
  with the MCP server
- `toolSuccess` & `toolError`: Helper functions for creating standardized
  response objects
- `mergeShapes`: Utility to merge multiple Zod schema shapes into a single shape

### Using the Tool Factory

```typescript
import { createTool, toolSuccess, toolError } from '../shared/toolBuilder'

export function registerMyTools(client: SchwabApiClient, server: McpServer) {
	createTool(client, server, {
		name: 'myTool',
		schema: mySchema, // Zod schema for validating input
		handler: async (input, client) => {
			try {
				// Your tool implementation logic here
				const result = await client.someApi.someMethod(input)

				return toolSuccess({
					data: result,
					message: 'Successfully fetched data',
					source: 'myTool',
				})
			} catch (error) {
				return toolError(error, { source: 'myTool' })
			}
		},
	})
}
```

### Token Management

Token validation is handled automatically by the tool factory. If a token is
invalid, the tool will attempt to refresh it before proceeding. If token refresh
fails, the tool will continue execution in a "best-effort" mode, allowing
operations that don't require authentication to still work.

To initialize the token manager:

```typescript
import { initializeTokenManager } from '../auth'

// Initialize at application startup
// Token management is centralized in the TokenStateMachine instance within MyMCP
initializeTokenManager(tokenManagerInstance)
```

### Response Formatting

The tool factory automatically formats responses into the standard MCP content
array format, supporting both success and error cases. The format is:

```typescript
// Success
{
  content: [
    { type: 'text', text: 'Success message' },
    { type: 'text', text: JSON.stringify(data, null, 2) }
  ]
}

// Error
{
  content: [
    { type: 'text', text: 'Error message' }
  ],
  isError: true
}
```

### Error Handling

Errors are logged and formatted consistently across all tools. The tool factory
catches exceptions at multiple levels:

1. Token validation errors (non-fatal)
2. Input validation errors
3. Handler execution errors
4. Unexpected errors

Each error type is properly logged and formatted for the MCP server.

