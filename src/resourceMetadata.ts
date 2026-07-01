import type { Request, Response } from "express";

export interface ResourceMetadataOptions {
  /** The MCP server's own canonical URL, e.g. "https://mcp.example.com". */
  resource: string;
  /** Base URL of the mcpauth server acting as the authorization server. */
  issuer?: string;
  scopesSupported?: string[];
}

const DEFAULT_ISSUER = "https://getmcpauth.dev";

// RFC 9728 OAuth Protected Resource Metadata. An MCP client that hits a
// 401 reads this (via the WWW-Authenticate header's resource_metadata
// hint, or the well-known path) to learn which authorization server to
// register/authenticate against — this is what makes setup driven by a
// single registrationSecret rather than five hardcoded endpoint URLs.
export function protectedResourceMetadata(options: ResourceMetadataOptions) {
  return {
    resource: options.resource,
    authorization_servers: [options.issuer ?? DEFAULT_ISSUER],
    bearer_methods_supported: ["header"],
    ...(options.scopesSupported ? { scopes_supported: options.scopesSupported } : {}),
  };
}

// Convenience Express handler — mount at
// GET /.well-known/oauth-protected-resource
export function mcpAuthResourceMetadataHandler(options: ResourceMetadataOptions) {
  const metadata = protectedResourceMetadata(options);
  return (_req: Request, res: Response) => {
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json(metadata);
  };
}
