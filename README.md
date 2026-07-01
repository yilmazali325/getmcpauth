# mcpauth

Drop-in OAuth 2.1 + Dynamic Client Registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)) for MCP servers, backed by [mcpauth](https://getmcpauth.dev).

Wraps the official [`@modelcontextprotocol/sdk`](https://www.npmjs.com/package/@modelcontextprotocol/sdk)'s `requireBearerAuth` middleware so unauthenticated or invalid requests get rejected with a spec-correct `401` before they ever reach your MCP server's handlers.

## Install

```
npm install getmcpauth
```

## Usage

```ts
import express from "express";
import { mcpAuth } from "getmcpauth";

const app = express();

app.use(
  "/mcp",
  mcpAuth({ registrationSecret: process.env.MCPAUTH_SECRET })
);

// Unauthenticated or invalid requests never reach this handler.
app.post("/mcp", handleMcpRequest);
```

Get a `registrationSecret` by creating a project at [getmcpauth.dev/dashboard](https://getmcpauth.dev/dashboard) — it's your MCP server's credential for both Dynamic Client Registration and token verification.

MCP clients (Claude, ChatGPT, custom agent frameworks) then discover your auth setup automatically via `/.well-known/oauth-authorization-server` — no manual client configuration needed.

## API

- **`mcpAuth(options)`** — the middleware above. Successful token verifications are cached in-process (default 30s) so a chatty agent conversation doesn't trigger a network round trip on every tool call.
- **`McpAuthTokenVerifier`** — implements the official SDK's `OAuthTokenVerifier` interface directly, for non-Express use.
- **`mintToken(options)`** — for MCP servers embedded in a product that already has its own users: your backend, which already knows who its logged-in user is, mints a token server-to-server without routing that user through mcpauth's own login.
- **`protectedResourceMetadata(options)` / `mcpAuthResourceMetadataHandler(options)`** — RFC 9728 resource-metadata helpers.

Full docs: [getmcpauth.dev/docs](https://getmcpauth.dev/docs)

## License

MIT
