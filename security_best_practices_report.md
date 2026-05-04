# Focused Security Audit: rfc8693-external-idp-token-exchange

## Executive Summary

The branch introduces useful RFC 8693 and external IdP support, but the new stateless JWT path is broader than the resource-scoped token-exchange model implies. The highest-risk issue is that the gateway now accepts any Obot-signed JWT as API authentication without validating audience or token purpose. Combined with the new external IdP exchange and MCP proxy JWT minting, this can turn resource-specific or downstream-only tokens into general Obot bearer tokens if they are obtained or replayed.

Remediation status: fixed in the current working tree. Token purpose and audience are now enforced at API/gateway authentication boundaries, external IdP exchange is bound to validated MCP Gateway resources (`/mcp-connect` or `/mcp-connect/{mcp_id}`), and external IdP provider defaults now fail closed unless an operator configures a tenant/domain policy or an explicit allow-all override.

Focused tests run:

```bash
go test ./pkg/api/handlers/mcpgateway/oauth ./pkg/gateway/server ./pkg/jwt/persistent ./pkg/controller/handlers/nanobotagent ./pkg/mcp
```

Result: passed. The first sandboxed run failed because the Go build cache under `~/Library/Caches/go-build` was not writable from the workspace sandbox; the same command passed with normal cache access.

## High Severity

### SEC-1: Obot-signed JWTs are accepted as gateway/API credentials without audience or purpose validation

- Rule ID: GO-AUTH-001
- Severity: High
- Location: `pkg/gateway/server/tokenreview.go`, `gatewayTokenReview.AuthenticateRequest`, lines 43-67; `pkg/jwt/persistent/persistent.go`, `TokenService.DecodeToken`, lines 261-265 and 297-308; `pkg/api/handlers/mcpgateway/handler.go`, `Handler.Proxy`, lines 79-89.
- Evidence:

```go
if tokenCtx, err := g.tokenService.DecodeToken(req.Context(), bearer); err == nil {
    return &authenticator.Response{User: &user.DefaultInfo{
        Name: tokenCtx.UserName,
        UID: tokenCtx.UserID,
        Groups: tokenCtx.UserGroups,
    }}, true, nil
}
```

```go
tk, err := jwt.Parse(token, keyFunc, jwt.WithIssuer(t.serverURL))
```

```go
claims := jwt.MapClaims{
    "aud": audience,
    "sub": req.User.GetUID(),
    "MCPID": serverConfig.MCPServerName,
}
_, token, err := h.tokenService.NewTokenWithClaims(req.Context(), claims)
```

- Impact: Any token signed by the Obot persistent token service and carrying the Obot issuer is treated as an authenticated gateway/API credential, regardless of `aud`, `MCPID`, or intended use. Tokens minted for a downstream MCP shim are valid for 75 minutes and could be replayed against Obot if a downstream server, proxy log, or browser/dev tooling exposes them. External IdP exchange tokens are also accepted as general Obot credentials rather than as a constrained RFC 8693 result.
- Fix: Split token purposes and enforce them at authentication boundaries. For API/gateway auth, require `aud == serverURL` and a purpose/scope such as `TokenType == "gateway_api"` or equivalent. For MCP proxy tokens, set a distinct purpose such as `mcp_proxy` and reject it in `gatewayTokenReview`. Prefer adding a Decode/Authenticate variant that validates expected audience and token type instead of using the generic `DecodeToken` in all contexts.
- Mitigation: Keep proxy JWT TTLs short, avoid forwarding these tokens to arbitrary third-party servers, redact Authorization headers from downstream logs, and add tests that prove an MCP-audience JWT is rejected by gateway/API auth.
- False positive notes: This is mitigated only if every API authorization check independently rejects users with missing/empty role groups and if downstream MCP services cannot expose bearer headers. That is not a safe boundary to rely on for a token service.

### SEC-2: External IdP token exchange bypasses resource/requested-token validation and mints a broad Obot token

- Rule ID: GO-AUTH-002
- Severity: High
- Location: `pkg/api/handlers/mcpgateway/oauth/token.go`, `doTokenExchange`, lines 361-372; `doExternalIdPTokenExchange`, lines 791-823.
- Evidence:

```go
if subjectTokenType == tokenTypeIDToken {
    return h.doExternalIdPTokenExchange(req, oauthClient, subjectToken)
}
```

```go
jwtClaims := jwt.MapClaims{
    "sub": fmt.Sprintf("%d", user.ID),
    "aud": h.baseURL,
    "UserGroups": strings.Join(user.Role.Groups(), ","),
}
```

- Impact: The `id_token` path returns before the normal `requested_token_type` and `resource` checks. An allowlisted OAuth client can exchange a valid IdP token for a one-hour JWT with `aud` set to the whole Obot base URL, with role groups embedded. This is broader than a resource-bound RFC 8693 exchange and makes client/resource confusion more likely.
- Fix: Validate `requested_token_type` and `resource` before branching on `subject_token_type`, or pass them into `doExternalIdPTokenExchange`. Bind the issued token to the requested MCP Gateway resource and the OAuth client policy, using `/mcp-connect` for gateway-scoped MCP access or `/mcp-connect/{mcp_id}` for a single-server token. Set `MCPID` where applicable, and reject requests without an explicit allowed resource. If the intended feature is general login by external IdP, expose it as a distinct, documented grant/endpoint with a separate allowlist.
- Mitigation: Configure `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` narrowly and do not allow public clients to use this flow until token audience/resource checks are enforced.
- False positive notes: If this branch intentionally wants a generic Obot login token, the implementation should still make that explicit in config and tests instead of silently treating an RFC 8693 exchange as a general auth flow.

## Medium Severity

### SEC-3: External IdP defaults are fail-open for user provisioning and tenant/domain boundaries once a client is allowlisted

- Rule ID: GO-CONFIG-001
- Severity: Medium
- Location: `pkg/api/handlers/mcpgateway/oauth/handler.go`, `NewExternalIdPConfig`, lines 25-40; `pkg/api/handlers/mcpgateway/oauth/google.go`, lines 38-48 and 82-117; `pkg/api/handlers/mcpgateway/oauth/entra.go`, lines 44-66 and 192-198; `pkg/api/handlers/mcpgateway/oauth/oidc_idp.go`, lines 58-66 and 155-177.
- Evidence:

```go
config := ExternalIdPConfig{
    AutoProvision: true, // Default to enabled for development convenience
}
```

```go
if domains := os.Getenv("OBOT_GOOGLE_ALLOWED_DOMAINS"); domains != "" {
    validator.allowedDomains = strings.Split(domains, ",")
}
```

```go
if tenantID == "" {
    tenantID = "common" // Multi-tenant by default
}
```

- Impact: After an operator enables the feature for any OAuth client, user creation defaults to on. Google and generic OIDC domain restrictions are optional, and Entra defaults to multi-tenant unless explicit tenant/domain restrictions are set. A valid token for the configured IdP client ID can therefore create an Obot user unless the deployment has carefully set all optional allowlists.
- Fix: Default `OBOT_EXTERNAL_IDP_AUTO_PROVISION` to false. For Google/OIDC, require an allowed domain/hosted-domain list unless an explicit `ALLOW_CONSUMER_ACCOUNTS` flag is set. For Entra, require `OBOT_ENTRA_ALLOWED_TENANTS` or a single explicit tenant for production, and avoid `SkipIssuerCheck` without a verified post-check that the token issuer and tenant are in policy.
- Mitigation: In current deployments, set `OBOT_EXTERNAL_IDP_AUTO_PROVISION=false` unless self-service signup is intended, and configure `OBOT_GOOGLE_ALLOWED_DOMAINS`, `OBOT_GOOGLE_ALLOWED_HDS`, `OBOT_ENTRA_ALLOWED_TENANTS`, `OBOT_ENTRA_ALLOWED_DOMAINS`, or `OBOT_OIDC_ALLOWED_DOMAINS` as applicable.
- False positive notes: If the intended product behavior is open self-service signup, this should be documented as a deliberate deployment mode and separated from the default production behavior.

## Additional Notes

The new MCP OAuth `return_url` allowlist has good basic protections: absolute HTTP(S) parsing, exact scheme/host matching, path-prefix matching with path-boundary handling, and tests for host-prefix confusion. I did not find a branch-specific open redirect in that path.
