import type { OAuthTokenVerifier } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidTokenError, ServerError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

export interface McpAuthOptions {
  /**
   * The Project's registration secret from mcpauth (the same value used
   * for Dynamic Client Registration). Used here to authenticate calls to
   * mcpauth's /introspect endpoint.
   */
  registrationSecret: string;
  /**
   * Base URL of the mcpauth server. Defaults to the hosted service.
   */
  issuer?: string;
  /**
   * How long a verified token's result is cached in-process before the
   * next call re-checks with mcpauth, in milliseconds. Every uncached
   * call costs a network round trip and a database query on mcpauth's
   * end — an MCP server can easily make dozens of tool calls per agent
   * conversation, so this cuts real request volume, not just latency.
   * Trade-off: a revoked token can stay accepted for up to this long.
   * Default 30s. Set to 0 to disable caching entirely.
   */
  cacheTtlMs?: number;
}

interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  sub?: string;
  exp?: number;
}

const DEFAULT_ISSUER = "https://getmcpauth.dev";
const DEFAULT_CACHE_TTL_MS = 30_000;
// Hard cap so a long-running MCP server process handling many distinct
// tokens doesn't grow this cache unboundedly — oldest entries are evicted
// first once the cap is hit, independent of their TTL.
const MAX_CACHE_ENTRIES = 10_000;

interface CacheEntry {
  authInfo: AuthInfo;
  expiresAtMs: number;
}

// Implements the MCP SDK's OAuthTokenVerifier contract by calling
// mcpauth's RFC 7662 /introspect endpoint. Successful verifications are
// cached in-process for cacheTtlMs — this is the one thing the SDK
// actually does — everything else (the middleware, the resource metadata
// helper) is convenience wrapping around this.
export class McpAuthTokenVerifier implements OAuthTokenVerifier {
  private readonly registrationSecret: string;
  private readonly introspectUrl: string;
  private readonly cacheTtlMs: number;
  private readonly cache = new Map<string, CacheEntry>();

  constructor(options: McpAuthOptions) {
    this.registrationSecret = options.registrationSecret;
    this.introspectUrl = new URL("/api/oauth/introspect", options.issuer ?? DEFAULT_ISSUER).toString();
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const cached = this.cache.get(token);
    if (cached && cached.expiresAtMs > Date.now()) {
      return cached.authInfo;
    }

    const response = await fetch(this.introspectUrl, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.registrationSecret}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ token }).toString(),
    });

    if (!response.ok) {
      // A non-200 here means our own introspection call is misconfigured
      // or unreachable (bad registrationSecret, network issue) — that's
      // our fault, not the caller's, so surface it as a 500 rather than
      // telling every legitimate caller their token is invalid.
      throw new ServerError(`mcpauth introspection request failed with status ${response.status}`);
    }

    const data = (await response.json()) as IntrospectionResponse;
    if (!data.active) {
      // Deliberately not cached — a token that's invalid now (e.g. not
      // yet propagated after a fresh /token call) shouldn't stay rejected
      // for the full TTL once it does become valid.
      throw new InvalidTokenError("token is invalid, expired, or revoked");
    }

    const authInfo: AuthInfo = {
      token,
      clientId: data.client_id ?? "",
      scopes: data.scope ? data.scope.split(" ") : [],
      expiresAt: data.exp,
      extra: { sub: data.sub },
    };

    if (this.cacheTtlMs > 0) this.setCached(token, authInfo);
    return authInfo;
  }

  private setCached(token: string, authInfo: AuthInfo): void {
    if (this.cache.size >= MAX_CACHE_ENTRIES) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) this.cache.delete(oldestKey);
    }
    this.cache.set(token, { authInfo, expiresAtMs: Date.now() + this.cacheTtlMs });
  }
}
