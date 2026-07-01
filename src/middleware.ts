import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { RequestHandler } from "express";
import { McpAuthTokenVerifier, type McpAuthOptions } from "./verifier.js";

export interface McpAuthMiddlewareOptions extends McpAuthOptions {
  /** Scopes every request must carry, in addition to whatever /oauth/authorize granted. */
  requiredScopes?: string[];
  /** Advertised in the WWW-Authenticate header on 401s, per RFC 9728. */
  resourceMetadataUrl?: string;
}

// The actual "10 minutes to add OAuth" entry point — drop this in front of
// an MCP server's HTTP routes and every request is checked against
// mcpauth before it reaches your handlers.
//
//   app.use("/mcp", mcpAuth({ registrationSecret: process.env.MCPAUTH_SECRET }));
//
export function mcpAuth(options: McpAuthMiddlewareOptions): RequestHandler {
  const verifier = new McpAuthTokenVerifier(options);
  return requireBearerAuth({
    verifier,
    requiredScopes: options.requiredScopes,
    resourceMetadataUrl: options.resourceMetadataUrl,
  });
}
