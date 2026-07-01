export interface MintTokenOptions {
  /** The Project's registration secret — same value used for DCR and /introspect. */
  registrationSecret: string;
  /** Base URL of the mcpauth server. Defaults to the hosted service. */
  issuer?: string;
  /** Which registered MCP client this token is for. */
  clientId: string;
  /** The Project's own opaque user id — mcpauth never authenticates this identity itself. */
  subject: string;
  scopes?: string[];
}

export interface MintedTokenPair {
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: number;
  refreshToken: string;
  scope: string;
}

const DEFAULT_ISSUER = "https://getmcpauth.dev";

// For a Project embedded in a product with its own users (already
// authenticated through the Project's own login, not GitHub-via-mcpauth):
// the Project's backend calls this directly to mint a token for a user it
// already knows, instead of routing that user through mcpauth's
// /oauth/authorize consent screen. See /api/oauth/token/exchange.
export async function mintToken(options: MintTokenOptions): Promise<MintedTokenPair> {
  const url = new URL("/api/oauth/token/exchange", options.issuer ?? DEFAULT_ISSUER);

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${options.registrationSecret}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      client_id: options.clientId,
      subject: options.subject,
      scopes: options.scopes ?? [],
    }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`mcpauth token exchange failed with status ${response.status}: ${body}`);
  }

  const data = await response.json();
  return {
    accessToken: data.access_token,
    tokenType: "Bearer",
    expiresIn: data.expires_in,
    refreshToken: data.refresh_token,
    scope: data.scope,
  };
}
