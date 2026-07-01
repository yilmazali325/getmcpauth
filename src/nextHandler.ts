import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { McpAuthTokenVerifier, type McpAuthOptions } from "./verifier.js";

export interface McpAuthNextHandlerOptions extends McpAuthOptions {
  /**
   * Builds a fresh MCP server instance per request. Called only after the
   * request's Bearer token has been verified — unauthenticated requests
   * never reach this.
   */
  buildServer: () => McpServer;
  /**
   * Advertised in the WWW-Authenticate header on 401s, per RFC 9728 —
   * typically your own `/.well-known/oauth-protected-resource` route,
   * built with `protectedResourceMetadata()`.
   */
  resourceMetadataUrl?: string;
}

function unauthorizedResponse(errorDescription: string, resourceMetadataUrl?: string): Response {
  const wwwAuthenticateParts = [`error="invalid_token"`, `error_description="${errorDescription}"`];
  if (resourceMetadataUrl) wwwAuthenticateParts.push(`resource_metadata="${resourceMetadataUrl}"`);

  return new Response(JSON.stringify({ error: "invalid_token", error_description: errorDescription }), {
    status: 401,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Bearer ${wwwAuthenticateParts.join(", ")}`,
    },
  });
}

/**
 * Builds a Web Standard `(request: Request) => Promise<Response>` handler
 * for a Next.js (or any Fetch-API-based) MCP server route — the same
 * shape mcpauth's own live demo server uses in production. Wraps
 * `WebStandardStreamableHTTPServerTransport` from the official MCP SDK
 * with mcpauth's token verification in front of it.
 *
 * ```ts
 * // app/api/mcp/route.ts
 * const handler = createMcpAuthHandler({
 *   registrationSecret: process.env.MCPAUTH_SECRET!,
 *   buildServer: () => {
 *     const server = new McpServer({ name: "my-server", version: "1.0.0" });
 *     server.registerTool(...);
 *     return server;
 *   },
 * });
 *
 * export { handler as GET, handler as POST, handler as DELETE };
 * ```
 */
export function createMcpAuthHandler(
  options: McpAuthNextHandlerOptions,
): (request: Request) => Promise<Response> {
  const verifier = new McpAuthTokenVerifier(options);

  return async function handleRequest(request: Request): Promise<Response> {
    const authHeader = request.headers.get("authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return unauthorizedResponse("Missing Authorization header", options.resourceMetadataUrl);
    }
    const token = authHeader.slice(7);

    // verifyAccessToken never returns null/undefined — it resolves to a
    // valid AuthInfo or throws.
    let authInfo;
    try {
      authInfo = await verifier.verifyAccessToken(token);
    } catch {
      return unauthorizedResponse("Token is invalid, expired, or revoked", options.resourceMetadataUrl);
    }

    const transport = new WebStandardStreamableHTTPServerTransport();
    const server = options.buildServer();
    await server.connect(transport);

    return transport.handleRequest(request, { authInfo });
  };
}
