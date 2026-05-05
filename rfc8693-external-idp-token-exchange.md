# RFC 8693 External IdP Token Exchange

## Summary

This branch adds an RFC 8693 token exchange path that lets an external client application exchange a validated external Identity Provider ID token for an Obot-issued bearer token that can call the MCP Gateway and, when registry authentication is enabled, the read-only MCP Registry API.

The primary use case is service-to-Obot MCP access without an interactive Obot browser login:

1. A client application authenticates a user with an external IdP such as Google, Microsoft Entra ID, Dex, Keycloak, Auth0, or another OIDC provider.
2. The client receives an ID token from that IdP.
3. The client POSTs that ID token to Obot's OAuth token endpoint using the RFC 8693 token exchange grant.
4. Obot validates the external token with the matching provider validator.
5. Obot maps or provisions the external identity into its gateway identity store.
6. Obot returns an Obot-signed access token scoped to the requested resource: the registry API, `/mcp-connect`, or a single `/mcp-connect/{mcp_id}` resource.
7. The client uses that access token as `Authorization: Bearer ...` when calling the corresponding registry or MCP Gateway resource.

The returned token is a JWT signed by Obot's persistent token service, but it is intentionally returned as an OAuth access token:

```json
{
  "access_token": "<obot-signed-jwt>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

It is not a general Obot API login token. It is bound to either the read-only registry API or the MCP Gateway path and cannot be replayed against normal Obot API routes.

## Platform Context

Obot is an MCP platform with four main responsibilities:

| Area | Responsibility |
|---|---|
| MCP hosting | Deploy and manage MCP servers, typically on Kubernetes |
| MCP registry | Publish and control access to MCP server catalog entries |
| MCP gateway | Expose MCP servers behind a single OAuth-aware gateway and proxy |
| Obot Chat | Provide the built-in project, thread, task, and chat UI that uses MCP servers |

The external IdP token exchange flow belongs to the gateway/OAuth layer. It lets applications that already authenticated a user elsewhere call Obot-hosted MCP servers without sending the user through Obot's browser login.

Typical deployment shape:

```text
External app or MCP client
    -> Obot /oauth/token
    -> Obot /v0.1/servers
    -> Obot /mcp-connect/{mcp_id}
    -> Obot-managed MCP server runtime
```

In a Kubernetes deployment, Obot usually sits behind an ingress, stores platform data in PostgreSQL, and deploys containerized MCP servers as service-backed pods. A deployment may also use a broker IdP such as Dex in front of Google and Entra ID, but this branch does not require Dex. Obot can validate Google, Entra ID, and generic OIDC ID tokens side by side.

## What This Does

The feature extends `POST /oauth/token` with support for:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token_type=urn:ietf:params:oauth:token-type:id_token
requested_token_type=urn:ietf:params:oauth:token-type:access_token
```

For `subject_token_type=id_token`, Obot treats `subject_token` as an external IdP ID token. The token is routed to a provider-specific validator based on the unverified `iss` claim, then fully validated by that provider validator.

Supported validators in this branch:

| Provider | Issuer matching | Validator file | Token audience requirement |
|---|---|---|---|
| Google | `https://accounts.google.com`, `accounts.google.com` | `pkg/api/handlers/mcpgateway/oauth/google.go` | Must match `OBOT_GOOGLE_CLIENT_ID` |
| Microsoft Entra ID | `https://login.microsoftonline.com/`, `https://sts.windows.net/` | `pkg/api/handlers/mcpgateway/oauth/entra.go` | Must match `OBOT_ENTRA_CLIENT_ID` |
| Generic OIDC | Exact configured `OBOT_OIDC_ISSUER` | `pkg/api/handlers/mcpgateway/oauth/oidc_idp.go` | Must match one entry in `OBOT_OIDC_CLIENT_ID` |

After validation, Obot creates an internal `TokenContext` with:

| Claim/context | Meaning |
|---|---|
| `sub` / `UserID` | Obot gateway user ID |
| `email`, `name`, `picture` | User profile fields from the mapped Obot user and external claims |
| `AuthProviderNamespace`, `AuthProviderName`, `AuthProviderUserID` | External identity mapping fields |
| `MCPID` | MCP server ID parsed from a single-server resource, or empty for registry and gateway-scoped `/mcp-connect` resources |
| `aud` | Canonical Obot resource URL: `{configured Obot base URL}` for the registry API, `{configured Obot base URL}/mcp-connect`, or `{configured Obot base URL}/mcp-connect/{mcp_id}` |
| `TokenType` | `oauth_access` |
| `exp` | One hour after issuance |

The token service enforces token purpose, audience, and request path before accepting tokens. `oauth_access` tokens are valid only for same-origin registry or `/mcp-connect` requests matching their audience. A registry-scoped token can call only read-only `GET`/`HEAD` requests under `/v0.1`. A token scoped to `/mcp-connect` can call any MCP server behind the gateway, while a token scoped to `/mcp-connect/{mcp_id}` can call only that server and its subpaths. All `oauth_access` forms are rejected for normal Obot API routes such as `/api/...`.

## Where It Is Implemented

The main request flow is in:

| File | Responsibility |
|---|---|
| `pkg/api/handlers/mcpgateway/oauth/handler.go` | Registers OAuth endpoints and loads external IdP configuration |
| `pkg/api/handlers/mcpgateway/oauth/token.go` | Handles `POST /oauth/token`, RFC 8693 validation, external IdP exchange, and resource-bound token issuance |
| `pkg/api/handlers/mcpgateway/oauth/idp_validator.go` | Routes external JWTs to the right validator by `iss` |
| `pkg/api/handlers/mcpgateway/oauth/google.go` | Validates Google ID tokens |
| `pkg/api/handlers/mcpgateway/oauth/entra.go` | Validates Entra ID tokens |
| `pkg/api/handlers/mcpgateway/oauth/oidc_idp.go` | Validates generic OIDC ID tokens |
| `pkg/jwt/persistent/persistent.go` | Mints and validates Obot JWTs, including token purpose and request audience checks |
| `pkg/gateway/server/tokenreview.go` | Allows only `gateway_api` Obot JWTs for gateway/API stateless auth |
| `pkg/api/handlers/mcpgateway/handler.go` | MCP Gateway proxy path that consumes accepted tokens and forwards MCP proxy tokens downstream |

The same `POST /oauth/token` handler also supports other token exchange inputs:

| `subject_token_type` | Use |
|---|---|
| `urn:ietf:params:oauth:token-type:id_token` | External IdP ID token to Obot registry or MCP access token |
| `urn:obot:token-type:api-key` | Obot API key to downstream MCP token, subject to API key MCP access checks |
| `urn:ietf:params:oauth:token-type:jwt` | Existing Obot JWT to another MCP resource token, used for composite/server-to-server flows |

This document focuses on the external IdP `id_token` flow.

## Where It Is Used

The returned access token is used against the resource requested during token exchange.

For authenticated MCP Registry discovery, request the registry resource and use the returned token for read-only Registry API calls:

```bash
curl -sS https://obot.example.com/v0.1/servers \
  -H "Authorization: Bearer ${OBOT_REGISTRY_TOKEN}"
```

The registry token is accepted only for `GET`/`HEAD` requests under `/v0.1`; it is not accepted for `/api/...` management endpoints and is not accepted for `/mcp-connect`.

For MCP Gateway access, use the gateway-scoped audience. The same token can be used for any MCP server path behind the same Obot gateway:

```http
GET /mcp-connect/{mcp_id} HTTP/1.1
Host: obot.example.com
Authorization: Bearer <obot_access_token>
```

and for transport subpaths:

```http
GET /mcp-connect/{mcp_id}/sse HTTP/1.1
Host: obot.example.com
Authorization: Bearer <obot_access_token>
```

The resource binding is path based:

| Token audience | Request path | Accepted |
|---|---|---|
| `https://obot.example.com` | `GET /v0.1/servers` | Yes |
| `https://obot.example.com` | `GET /v0.1/servers/server1/versions` | Yes |
| `https://obot.example.com` | `POST /v0.1/servers` | No |
| `https://obot.example.com` | `/api/mcp-servers` | No |
| `https://obot.example.com` | `/mcp-connect/server1` | No |
| `https://obot.example.com/mcp-connect` | `/mcp-connect/server1` | Yes |
| `https://obot.example.com/mcp-connect` | `/mcp-connect/server2/sse` | Yes |
| `https://obot.example.com/mcp-connect` | `/api/projects` | No |
| `https://obot.example.com/mcp-connect` | `/v0.1/servers` | No |
| `https://obot.example.com/mcp-connect/server1` | `/mcp-connect/server1` | Yes |
| `https://obot.example.com/mcp-connect/server1` | `/mcp-connect/server1/sse` | Yes |
| `https://obot.example.com/mcp-connect/server1` | `/mcp-connect/server2` | No |
| `https://obot.example.com/mcp-connect/server1` | `/api/projects` | No |
| `https://other.example.com/mcp-connect/server1` | `/mcp-connect/server1` on `obot.example.com` | No |

When the MCP Gateway proxies the request to the target MCP server, it replaces the client's bearer token with an internal MCP proxy JWT. That downstream token is marked as `mcp_proxy` and is deliberately rejected by Obot API authentication if replayed back to Obot.

## MCP Gateway Context

The token returned by this flow is useful because the MCP Gateway is the public entry point for Obot-managed MCP servers.

Proxy flow:

```text
Client request
    -> /mcp-connect/{mcp_id}/*
    -> Obot authenticates the bearer token
    -> Obot ensures the target MCP server is deployed
    -> Obot creates an internal MCP proxy JWT for the downstream server
    -> Obot replaces the Authorization header
    -> MCP server handles the request
```

Obot supports several MCP server deployment models:

| Type | Storage model | Instance model | Transport |
|---|---|---|---|
| Single-user | `MCPServerCatalogEntry` | One instance per user | STDIO or HTTP |
| Multi-user | `MCPServer` | Shared instance | HTTP |
| Remote | `MCPServerCatalogEntry` | External server | HTTP |
| Composite | `MCPServerCatalogEntry` | Virtual server delegating to component servers | HTTP |

Supported runtime kinds include `npx`, `uvx`, `containerized`, `remote`, and `composite`.

For containerized MCP servers on Kubernetes, Obot creates the runtime objects needed to expose the server internally, such as a Deployment, Service, and configuration Secret. Hardened deployments should keep MCP workloads non-root, drop Linux capabilities, use seccomp, and apply NetworkPolicies where the platform supports them.

Composite MCP servers need extra token-exchange behavior. A composite server may call component MCP servers. For those component calls, Obot can exchange an existing Obot JWT or API key into a token suitable for the component resource, validating that the component belongs to the composite before issuing or forwarding the token.

## Browser Login vs External Token Exchange

Obot has two distinct authentication paths that can share the same identity store.

| Path | Purpose | Provider model |
|---|---|---|
| Browser login | Interactive Obot UI and normal web session login | Obot's configured browser auth provider |
| RFC 8693 external IdP exchange | Programmatic Registry API discovery and MCP Gateway access by an external app that already has an IdP ID token | Multiple validators can be active in parallel |

Browser login establishes an Obot web session. External token exchange does not create a browser session; it returns a short-lived bearer token for an MCP resource.

The external flow routes incoming tokens by their `iss` claim:

```text
Dex ID token      -> POST /oauth/token -> generic OIDC validator -> Obot registry or MCP access token
Google ID token   -> POST /oauth/token -> Google validator       -> Obot registry or MCP access token
Entra ID token    -> POST /oauth/token -> Entra validator        -> Obot registry or MCP access token
```

If both paths map to the same auth provider namespace/name and provider user ID, they resolve to the same Obot identity. That means project access, role resolution, and audit attribution can be consistent across browser and programmatic access. If the browser provider and external token exchange provider use different identity keys, they will be separate identities unless explicitly linked in the gateway identity store.

## Operator Configuration

External token exchange is disabled unless both an OAuth client allowlist and at least one provider validator are configured.

### Common External IdP Settings

| Environment variable | Required | Meaning |
|---|---:|---|
| `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` | Yes | Comma-separated OAuth client IDs allowed to use external IdP exchange. Client IDs use Obot's `namespace:name` format, for example `default:oc1example`. Empty means no client can use this flow. |
| `OBOT_EXTERNAL_IDP_AUTO_PROVISION` | No | Defaults to false. If true, Obot creates a user/identity on first successful external token exchange. If false, the external identity must already exist. |

`OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` is a client application allowlist, not a user allowlist. User and tenant/domain restrictions come from the provider-specific settings below.

### Google Settings

| Environment variable | Required | Meaning |
|---|---:|---|
| `OBOT_GOOGLE_CLIENT_ID` | Yes, for Google | Expected Google ID token audience |
| `OBOT_GOOGLE_ALLOWED_DOMAINS` | Required unless override/HD set | Comma-separated allowed email domains, for example `example.com` |
| `OBOT_GOOGLE_ALLOWED_HDS` | Required unless override/domain set | Comma-separated Google Workspace hosted-domain values from the `hd` claim |
| `OBOT_GOOGLE_ALLOW_ALL_DOMAINS` | No | Explicit override. If true, the validator accepts any verified email domain for the configured Google client ID. |

Google validation uses Google's ID token library. It verifies signature, expiry, issuer, audience, and `email_verified`.

### Generic OIDC Settings

| Environment variable | Required | Meaning |
|---|---:|---|
| `OBOT_OIDC_ISSUER` | Yes, for OIDC | Exact issuer URL, trimmed of trailing slash |
| `OBOT_OIDC_CLIENT_ID` | Yes, for OIDC | Comma-separated accepted ID token audiences |
| `OBOT_OIDC_PROVIDER_NAME` | No | Provider name used internally and in logs. Defaults to `oidc`. |
| `OBOT_OIDC_AUTH_PROVIDER_NAME` | No | Auth provider identity name. Defaults to `{provider}-auth-provider`. |
| `OBOT_OIDC_ALLOWED_DOMAINS` | Required unless override set | Comma-separated allowed email domains |
| `OBOT_OIDC_ALLOW_ALL_DOMAINS` | No | Explicit override. If true, the validator accepts any verified email domain for the configured issuer and audience. |

Generic OIDC validation performs discovery from `OBOT_OIDC_ISSUER`, verifies signature/expiry/issuer, manually checks the token audience against `OBOT_OIDC_CLIENT_ID`, and requires `email` plus `email_verified=true`.

### Microsoft Entra ID Settings

| Environment variable | Required | Meaning |
|---|---:|---|
| `OBOT_ENTRA_CLIENT_ID` | Yes, for Entra | Expected Entra ID token audience |
| `OBOT_ENTRA_TENANT_ID` | Required unless allow-any set | Tenant ID expected in the `tid` claim. Can be `common` only with an additional tenant/domain policy or explicit allow-any override. |
| `OBOT_ENTRA_ALLOWED_TENANTS` | No | Comma-separated allowed `tid` values |
| `OBOT_ENTRA_ALLOWED_DOMAINS` | No | Comma-separated allowed email/UPN domains |
| `OBOT_ENTRA_ALLOW_ANY_TENANT` | No | Explicit override. If true, missing `OBOT_ENTRA_TENANT_ID` is allowed and the validator uses `common`. |

Entra validation supports both v2 issuers under `https://login.microsoftonline.com/{tenant}/v2.0` and v1 issuers under `https://sts.windows.net/{tenant}/`. It extracts the user email from `email`, `preferred_username`, or `upn`, and uses `oid` as the stable external user ID when present.

### Example Deployment Configuration

This is a representative configuration for an Obot deployment that accepts Dex-issued ID tokens from an external application named `maistack-research`.

```yaml
config:
  OBOT_SERVER_HOSTNAME: "https://obot.data.example.com"
  OBOT_SERVER_MCPRUNTIME_BACKEND: "kubernetes"
  OBOT_SERVER_MCPBASE_IMAGE: "ghcr.io/obot-platform/mcp-images/phat:main"

  # External IdP token exchange
  OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS: "default:oc1maistack-langserve"
  OBOT_EXTERNAL_IDP_AUTO_PROVISION: "true"

  # Dex / generic OIDC validator
  OBOT_OIDC_ISSUER: "https://id.data.example.com"
  OBOT_OIDC_CLIENT_ID: "maistack-research"
  OBOT_OIDC_PROVIDER_NAME: "dex"
  OBOT_OIDC_ALLOWED_DOMAINS: "example.com"
```

In stricter production deployments, keep `OBOT_EXTERNAL_IDP_AUTO_PROVISION` unset or set to `false` and pre-link the external identities that should be allowed to use Obot.

## OAuth Client Requirements

The client application must authenticate to Obot's token endpoint as an Obot OAuth client.

The OAuth client must:

1. Exist in Obot storage as an `OAuthClient`.
2. Have a known `client_id` in the form `namespace:name`.
3. Have a client secret unless its registered token endpoint auth method permits otherwise.
4. Be listed in `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS`.
5. Be allowed to use the token exchange grant if its manifest explicitly restricts grant types.

The token endpoint supports both of these client authentication styles:

```http
Authorization: Basic base64(urlencode(client_id) + ":" + urlencode(client_secret))
```

or:

```text
client_id=default:oc1example
client_secret=<secret>
```

The token endpoint path may be either:

```text
POST /oauth/token
POST /oauth/token/{mcp_id}
```

The external IdP exchange uses the `resource` parameter to determine the target audience. The `{mcp_id}` path parameter is not enough for the external IdP exchange path.

## Client Application Flow

### 1. Obtain an External ID Token

The client application first authenticates the user with its external IdP and obtains an ID token.

Important constraints:

| Provider | Client-side requirement |
|---|---|
| Google | Request an ID token whose `aud` matches `OBOT_GOOGLE_CLIENT_ID`. |
| Generic OIDC | Request an ID token whose `iss` is `OBOT_OIDC_ISSUER`, whose `aud` is one of `OBOT_OIDC_CLIENT_ID`, and whose claims include `email` and `email_verified=true`. |
| Entra ID | Request an ID token whose `aud` matches `OBOT_ENTRA_CLIENT_ID` and whose `tid`/domain satisfies the configured policy. |

Do not send an external provider access token as `subject_token`. This flow expects a JWT ID token.

### 2. Choose the Registry or MCP Gateway Audience

The client chooses the Obot audience it wants to access.

For authenticated MCP Registry discovery, use the registry resource advertised by Obot's protected-resource metadata:

```text
https://obot.example.com
```

Obot also accepts the explicit registry API forms and canonicalizes them to the Obot base URL:

```text
https://obot.example.com/v0.1
https://obot.example.com/v0.1/servers
```

For a flexible MCP client that discovers or connects to many servers behind the gateway, use the gateway-scoped resource:

```text
https://obot.example.com/mcp-connect
```

For a client that should be limited to one MCP server, use the single-server resource:

```text
https://obot.example.com/mcp-connect/{mcp_id}
```

The value must be an absolute URL, must target the same origin as Obot's configured base URL, and must be the registry resource, `/mcp-connect`, or start with `/mcp-connect/`.

Registry-scoped tokens are for authenticated read-only MCP Registry API discovery when `OBOT_SERVER_ENABLE_REGISTRY_AUTH=true`. They are valid only for `GET`/`HEAD` requests under `/v0.1`.

The gateway-scoped form is the normal choice for clients that use Obot as a flexible MCP gateway. It avoids forcing a client to perform one token exchange per MCP server during first-load or cache warmup. Obot still prevents API replay because this token is accepted only under `/mcp-connect`.

For registry-scoped tokens, Obot keeps the token audience at the Obot base URL:

```text
resource=https://obot.example.com/v0.1/servers
audience=https://obot.example.com
MCPID=
```

For gateway-scoped tokens, Obot keeps the token audience at `/mcp-connect`:

```text
resource=https://obot.example.com/mcp-connect
audience=https://obot.example.com/mcp-connect
MCPID=
```

For single-server tokens, subpaths are allowed in the request, but Obot canonicalizes the token audience to the first MCP path segment:

```text
resource=https://obot.example.com/mcp-connect/server1/sse
audience=https://obot.example.com/mcp-connect/server1
MCPID=server1
```

### 3. Exchange the ID Token

Example with `client_secret_post`:

```bash
curl -sS https://obot.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'client_id=default:oc1example' \
  --data-urlencode 'client_secret=CLIENT_SECRET' \
  --data-urlencode 'subject_token=EXTERNAL_ID_TOKEN' \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:id_token' \
  --data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'resource=https://obot.example.com/mcp-connect'
```

For authenticated registry discovery, exchange for the registry resource instead:

```bash
curl -sS https://obot.example.com/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'client_id=default:oc1example' \
  --data-urlencode 'client_secret=CLIENT_SECRET' \
  --data-urlencode 'subject_token=EXTERNAL_ID_TOKEN' \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:id_token' \
  --data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'resource=https://obot.example.com/v0.1/servers'
```

Example with HTTP Basic client authentication:

```bash
basic="$(printf '%s:%s' 'default:oc1example' 'CLIENT_SECRET' | base64)"

curl -sS https://obot.example.com/oauth/token \
  -H "Authorization: Basic ${basic}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'subject_token=EXTERNAL_ID_TOKEN' \
  --data-urlencode 'subject_token_type=urn:ietf:params:oauth:token-type:id_token' \
  --data-urlencode 'requested_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'resource=https://obot.example.com/mcp-connect'
```

`requested_token_type` is optional only when omitted. If present, it must be:

```text
urn:ietf:params:oauth:token-type:access_token
```

`resource` is required.

### 4. Use the Returned Access Token

Use the returned `access_token` as a bearer token only for the resource audience used during token exchange.

For a registry token:

```bash
curl -sS https://obot.example.com/v0.1/servers \
  -H "Authorization: Bearer ${OBOT_REGISTRY_TOKEN}"
```

For an MCP Gateway token:

```bash
curl -sS https://obot.example.com/mcp-connect/server1 \
  -H "Authorization: Bearer ${OBOT_ACCESS_TOKEN}"
```

For an MCP client using SSE or streamable HTTP, configure the transport URL as the MCP Gateway URL and attach the returned bearer token in the `Authorization` header.

The token is valid for the canonical resource and its allowed paths until expiry. A registry-scoped token can be reused for read-only `/v0.1` discovery. A gateway-scoped `/mcp-connect` token can be reused across MCP servers behind the same Obot gateway; a single-server `/mcp-connect/{mcp_id}` token is valid only for that server. Refresh by performing token exchange again with a fresh valid external IdP ID token.

### 5. Cache Tokens by Audience

Clients should cache exchanged tokens by user and audience until shortly before expiry.

For authenticated registry discovery, cache one registry token per user and Obot registry:

```text
cache key = user identity + https://obot.example.com
```

For the normal gateway-scoped MCP flow, cache one gateway token per user and Obot gateway:

```text
cache key = user identity + https://obot.example.com/mcp-connect
```

Do not create one token per MCP server unless the client intentionally asked for a single-server audience. A client that loads tools from many MCP servers should exchange once for the registry resource when discovery requires authentication and once for `/mcp-connect`, then reuse those bearer tokens for their separate purposes.

## End-to-End Example: External Service to Obot MCP

An external service such as `maistack-langserve` can use the flow like this:

```text
1. User logs in to the external service.
2. The external service authenticates the user with Dex, Google, Entra ID, or another OIDC provider.
3. The external service receives an ID token.
4. The external service calls Obot:

   POST https://obot.data.example.com/oauth/token
   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
   subject_token=<external ID token>
   subject_token_type=urn:ietf:params:oauth:token-type:id_token
   requested_token_type=urn:ietf:params:oauth:token-type:access_token
   resource=https://obot.data.example.com/v0.1/servers

5. Obot validates the external token, maps or provisions the user, and returns an Obot registry access token.
6. The external service uses that token to discover servers:

   GET https://obot.data.example.com/v0.1/servers

7. The external service performs a separate exchange for MCP Gateway access:

   POST https://obot.data.example.com/oauth/token
   grant_type=urn:ietf:params:oauth:grant-type:token-exchange
   subject_token=<external ID token>
   subject_token_type=urn:ietf:params:oauth:token-type:id_token
   requested_token_type=urn:ietf:params:oauth:token-type:access_token
   resource=https://obot.data.example.com/mcp-connect

8. Obot returns an Obot MCP Gateway access token.
9. The external service uses that token to call:

   https://obot.data.example.com/mcp-connect/{mcp_id}

10. Obot authenticates the access token, deploys or locates the MCP server, replaces the external bearer token with an internal MCP proxy JWT, and proxies the request.
11. The MCP server returns tool/resource results to the external service.
```

The user does not need to notice a separate Obot login step, but the request is still attributed to an Obot gateway identity.

## Identity Mapping

External identity mapping is based on:

| Field | Source |
|---|---|
| Auth provider namespace | Validator implementation, currently `default` |
| Auth provider name | Provider-specific validator |
| Provider user ID | External provider subject value |
| Email | External token email claim |
| User profile picture | External token picture claim when available |

Provider-specific external user IDs:

| Provider | External user ID |
|---|---|
| Google | ID token `sub` |
| Generic OIDC | ID token `sub` |
| Entra ID | `oid` when present, otherwise token `sub` |

If `OBOT_EXTERNAL_IDP_AUTO_PROVISION=false`, the mapped external identity must already exist. If no user is found, token exchange fails with `access_denied`.

If `OBOT_EXTERNAL_IDP_AUTO_PROVISION=true`, Obot calls `EnsureIdentity` to create or retrieve the user identity.

## Security Model

The implementation is intentionally scoped:

| Control | Behavior |
|---|---|
| OAuth client allowlist | Only `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` may use external IdP exchange. |
| Provider allowlists | Google/OIDC require domain policy unless explicitly overridden. Entra requires tenant policy unless explicitly overridden. |
| Token audience | External exchange tokens are bound to the registry API, `{configured Obot base URL}/mcp-connect`, or `{configured Obot base URL}/mcp-connect/{mcp_id}`. |
| Token purpose | External exchange tokens are `TokenType=oauth_access`. |
| API replay prevention | `oauth_access` tokens are rejected for normal Obot API paths such as `/api/...`; registry-scoped tokens are limited to read-only `/v0.1` requests. |
| MCP proxy replay prevention | Internal downstream proxy tokens are `TokenType=mcp_proxy` and are rejected by Obot API auth. |
| General API tokens | Only `TokenType=gateway_api` tokens with the Obot origin are accepted by gateway/API stateless JWT auth. |
| TTL | External exchange access tokens currently expire after one hour. |

The external token's `iss` claim is initially decoded without verification only to choose the validator. The selected validator then performs full token validation before any user or Obot token is created.

## Error Cases

Common failures:

| Cause | Result |
|---|---|
| `subject_token` missing | `invalid_request` |
| Unsupported `subject_token_type` | `invalid_request` |
| `requested_token_type` present but not `access_token` | `invalid_request` |
| `resource` missing | `invalid_request` |
| `resource` not absolute, wrong origin, or not the registry API, `/mcp-connect`, or `/mcp-connect/{mcp_id}` | `invalid_request` |
| OAuth client not listed in `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` | `unauthorized_client` |
| External token issuer unsupported | `invalid_grant` |
| External token signature/audience/expiry/domain/tenant validation fails | `invalid_grant` |
| Auto-provisioning disabled and identity does not exist | `access_denied` |

## Minimal Integration Checklist

For the Obot operator:

1. Create or identify the Obot OAuth client that the external app will use.
2. Add that client ID to `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS`.
3. Configure exactly the IdP validators needed by the deployment.
4. Configure domain or tenant restrictions, or make an explicit allow-all decision with the override flags.
5. Decide whether `OBOT_EXTERNAL_IDP_AUTO_PROVISION` should remain false or be explicitly enabled.
6. Share the Obot token endpoint, OAuth client credentials, registry resource URL, and MCP Gateway resource URL with the client application.

For the client application:

1. Authenticate the user with the external IdP.
2. Obtain an ID token, not an access token.
3. POST an RFC 8693 token exchange request to `https://obot.example.com/oauth/token`.
4. Include `resource=https://obot.example.com/v0.1/servers` for authenticated registry discovery.
5. Include `resource=https://obot.example.com/mcp-connect`, or `resource=https://obot.example.com/mcp-connect/{mcp_id}` when intentionally limiting the MCP token to one server.
6. Store returned Obot access tokens only for their short lifetime.
7. Use each token only as a bearer token for its matching registry or MCP Gateway resource.
