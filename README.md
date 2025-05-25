# Schwab MCP Server

A Model Context Protocol (MCP) server that provides comprehensive access to
Schwab's trading and market data APIs through a secure OAuth 2.0 authentication
flow. This server enables AI assistants like Claude to interact with Schwab
accounts to retrieve market data, manage trading operations, and access account
information.

## Overview

This MCP server acts as a bridge between AI assistants and the Schwab API,
providing:

- **Secure OAuth Authentication**: Implements Schwab's OAuth 2.0 flow with PKCE
  for secure authentication
- **Comprehensive Trading Tools**: Access to accounts, orders, quotes, and
  transactions
- **Market Data Tools**: Real-time quotes, price history, market hours, movers,
  and options chains
- **Account Privacy**: Built-in account identifier scrubbing to protect
  sensitive information
- **Enterprise-Ready**: Deployed on Cloudflare Workers with Durable Objects for
  state management

## Features

### Trading Tools

- **Account Management**
  - `getAccounts`: Retrieve all account information with positions
  - `getAccountNumbers`: Get list of account identifiers
- **Order Management**
  - `getOrders`: Fetch orders with filtering options
- **Market Quotes**
  - `getQuotes`: Get real-time quotes for multiple symbols
  - `getQuote`: Get detailed quote for a single symbol
- **Transaction History**
  - `getTransactions`: Retrieve transaction history with date filtering
  - `getTransaction`: Get details of a specific transaction

### Market Data Tools

- **Instrument Search**
  - `searchInstruments`: Search for securities by symbol with projections
- **Price History**
  - `getPriceHistory`: Get historical price data with customizable periods
- **Market Hours**
  - `getMarketHours`: Check market operating hours by date
  - `getMarket`: Get specific market information
- **Market Movers**
  - `getMovers`: Find top market movers by index
- **Options Chains**
  - `getOptionChain`: Retrieve options chain data with Greeks
  - `getOptionExpiration`: Get option expiration dates

### User Preferences

- `getUserPreference`: Retrieve user trading preferences and settings

## Prerequisites

1. **Schwab Developer Account**: Register at
   [Schwab Developer Portal](https://developer.schwab.com)
2. **Cloudflare Account**: For deployment (free tier available)
3. **Node.js**: Version 22.x or higher

## Getting Started

### Installation

```bash
git clone <repository-url>
cd schwab-mcp
npm install
```

### Configuration

#### 1. Create a Schwab App

1. Log in to the [Schwab Developer Portal](https://developer.schwab.com)
2. Create a new app with:
   - **App Name**: Your MCP server name
   - **Callback URL**:
     `https://schwab-mcp.<your-subdomain>.workers.dev/callback`
   - **App Type**: Personal or third-party based on your use case
3. Note your **App Key** (Client ID) and generate an **App Secret**

#### 2. Set Environment Variables

```bash
# Set production secrets via Wrangler
npx wrangler secret put SCHWAB_CLIENT_ID      # Your Schwab App Key
npx wrangler secret put SCHWAB_CLIENT_SECRET  # Your Schwab App Secret
npx wrangler secret put SCHWAB_REDIRECT_URI   # https://schwab-mcp.<your-subdomain>.workers.dev/callback
npx wrangler secret put COOKIE_ENCRYPTION_KEY # Generate with: openssl rand -hex 32
```

#### 3. Set up KV Namespace

```bash
# Create the KV namespace for storing OAuth tokens
npx wrangler kv:namespace create "OAUTH_KV"
```

Update `wrangler.jsonc` with the generated KV namespace ID.

### Deployment

```bash
# Deploy to Cloudflare Workers
npx wrangler deploy
```

Your MCP server will be available at
`https://schwab-mcp.<your-subdomain>.workers.dev`

### Testing with Inspector

Test your deployment using the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector@latest
```

Enter `https://schwab-mcp.<your-subdomain>.workers.dev/sse` and connect. You'll
be prompted to authenticate with Schwab.

## Usage

### Claude Desktop Configuration

### 1. Use Claude Integrations

1. Go to the [Claude Desktop](https://www.anthropic.com/docs/claude-desktop)
   settings
2. Click on the "Integrations" tab
3. Click on the "Add Custom Integration" button
4. Enter the integration name "Schwab"
5. Enter the MCP Server URL:
   `https://schwab-mcp.<your-subdomain>.workers.dev/sse`
6. Click on the "Add" button
7. Click "Connect" and the Schwab Authentication flow will start.

### 2. Add the MCP Server to your Claude Desktop configuration

Add the following to your Claude Desktop configuration file:

```json
{
	"mcpServers": {
		"schwab": {
			"command": "npx",
			"args": [
				"mcp-remote",
				"https://schwab-mcp.<your-subdomain>.workers.dev/sse"
			]
		}
	}
}
```

Restart Claude Desktop. When you first use a Schwab tool, a browser window will
open for authentication.

### Example Commands

Once connected, you can ask Claude to:

- "Show me my Schwab account balances"
- "Get a quote for AAPL"
- "What are today's market movers in the $SPX?"
- "Show me the options chain for TSLA"
- "Get my recent transactions from the last week"

### Local Development

For local development, create a `.dev.vars` file:

```env
SCHWAB_CLIENT_ID=your_development_app_key
SCHWAB_CLIENT_SECRET=your_development_app_secret
SCHWAB_REDIRECT_URI=http://localhost:8788/callback
COOKIE_ENCRYPTION_KEY=your_random_key
```

Run locally:

```bash
npm run dev
# or
wrangler dev
```

Connect to `http://localhost:8788/sse` using the Inspector.

## Architecture

### Technology Stack

- **Runtime**: Cloudflare Workers with Durable Objects
- **Authentication**: OAuth 2.0 with PKCE via
  `@cloudflare/workers-oauth-provider`
- **API Client**: `@sudowealth/schwab-api` for type-safe Schwab API access
- **MCP Framework**: `@modelcontextprotocol/sdk` with `workers-mcp` adapter
- **State Management**: KV storage for tokens, Durable Objects for session state

### Security Features

1. **OAuth 2.0 with PKCE**: Secure authentication flow preventing authorization
   code interception
2. **Token Management**: Automatic token refresh with secure storage in KV
3. **Account Scrubbing**: Sensitive account identifiers are automatically
   replaced with display names
4. **Cookie Encryption**: Client approval state encrypted with AES-256

### Project Structure

```
schwab-mcp/
├── src/
│   ├── index.ts           # Main entry point and MCP server setup
│   ├── auth/              # OAuth authentication flow
│   │   ├── handler.ts     # OAuth endpoint handlers
│   │   ├── client.ts      # Schwab auth client setup
│   │   └── ui/            # Approval dialog UI
│   ├── tools/             # MCP tool implementations
│   │   ├── market/        # Market data tools
│   │   └── trader/        # Trading account tools
│   ├── shared/            # Shared utilities
│   │   ├── accountScrubber.ts  # Account privacy protection
│   │   ├── logger.ts           # Centralized logging
│   │   └── toolBuilder.ts      # Tool registration framework
│   └── types/             # TypeScript type definitions
├── package.json
├── tsconfig.json
└── wrangler.jsonc        # Cloudflare Workers configuration
```

## Development

### Available Scripts

```bash
npm run dev        # Start development server
npm run deploy     # Deploy to Cloudflare
npm run typecheck  # Run TypeScript type checking
npm run lint       # Run ESLint
npm run format     # Format code with Prettier
npm run validate   # Run typecheck and lint
```

### Debugging

The server includes comprehensive logging. View logs in:

- **Development**: Terminal output
- **Production**: Cloudflare dashboard → Workers → Logs

### Error Handling

All API errors are caught and formatted with helpful context:

- Authentication errors prompt for re-authentication
- API errors include request IDs for troubleshooting
- Network errors are retried automatically

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT

## Acknowledgments

- Built with [Cloudflare Workers](https://workers.cloudflare.com/)
- Uses [Model Context Protocol](https://modelcontextprotocol.io/)
- Powered by
  [@sudowealth/schwab-api](https://www.npmjs.com/package/@sudowealth/schwab-api)
