# Multi-IdP Authentication in Obot: Dex vs Native Token Exchange

## Summary

Obot supports two separate authentication paths. **Browser-based login** (the admin-configured auth provider) is limited to a single IdP at a time. **RFC 8693 token exchange** (programmatic, for external services) natively supports multiple IdPs in parallel — including Google, Entra ID, and any OIDC-compliant provider (Dex, Keycloak, Auth0, etc.).

## The Two Authentication Paths

### Browser Login (Single Provider)

Obot's browser-based SSO flow uses OAuth2 redirect through a GPTScript-managed auth provider daemon. The admin configures exactly one provider (Google, GitHub, Entra ID, or Okta) through the Admin UI or API. Attempting to configure a second returns:

> *"only one authentication provider can be configured at a time"*

If your users need to choose between Google and Entra ID on the login screen, you would need either:
- **Dex** as an OIDC intermediary that federates both IdPs into a single provider endpoint
- A code change to remove Obot's single-provider constraint (the UI already renders a multi-provider login screen; only the backend guard blocks it)

### RFC 8693 Token Exchange (Multiple Providers)

The token exchange endpoint accepts ID tokens from external identity providers and returns Obot-signed JWTs. This path is designed for machine-to-machine and SSO integration scenarios where the calling service already has the user's IdP token.

**Multiple IdPs work simultaneously.** Validators register independently at startup based on environment variables. The incoming token's `iss` (issuer) claim routes it to the correct validator automatically:

| Incoming token issuer | Routed to |
|---|---|
| `https://accounts.google.com` | Google validator |
| `https://login.microsoftonline.com/{tenant}/v2.0` | Entra ID validator |
| `https://sts.windows.net/{tenant}/` | Entra ID validator (v1 issuer) |
| Any configured `OBOT_OIDC_ISSUER` (e.g., `https://id.data.mayflower.tech`) | Generic OIDC validator |

No Dex intermediary is needed because the dispatch happens natively inside Obot. Dex tokens work directly via the generic OIDC validator.

## When You Need Dex

| Scenario | Dex needed? |
|---|---|
| External services exchange Google or Entra tokens for Obot tokens | No - RFC 8693 handles both natively |
| External services exchange Dex/Keycloak/Auth0 tokens | No - configure the generic OIDC validator |
| Users log in via browser, all from one IdP | No - configure that single provider |
| Users log in via browser, choosing between Google and Entra | **Yes** - or remove the single-provider code constraint |

## Configuration

### Enabling Multi-IdP Token Exchange

Set the environment variables for each IdP you want to support. All can be active simultaneously.

**Google:**
```env
OBOT_GOOGLE_CLIENT_ID=123456789.apps.googleusercontent.com

# Optional restrictions
OBOT_GOOGLE_ALLOWED_DOMAINS=example.com,corp.example.com
OBOT_GOOGLE_ALLOWED_HDS=workspace.example.com
```

**Microsoft Entra ID:**
```env
OBOT_ENTRA_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
OBOT_ENTRA_TENANT_ID=common          # or a specific tenant GUID

# Optional restrictions
OBOT_ENTRA_ALLOWED_TENANTS=tenant-guid-1,tenant-guid-2
OBOT_ENTRA_ALLOWED_DOMAINS=example.com
```

**Generic OIDC (Dex, Keycloak, Auth0, etc.):**
```env
OBOT_OIDC_ISSUER=https://id.data.mayflower.tech
OBOT_OIDC_CLIENT_ID=obot-token-exchange

# Optional: customize provider identity in Obot (defaults: "oidc", "oidc-auth-provider")
OBOT_OIDC_PROVIDER_NAME=dex
OBOT_OIDC_AUTH_PROVIDER_NAME=dex-auth-provider

# Optional restrictions
OBOT_OIDC_ALLOWED_DOMAINS=mayflower.de,mayflower.tech
```

The OIDC validator performs standard OIDC discovery (`/.well-known/openid-configuration`) on first token validation, fetches JWKS keys, and caches the verifier. It validates the `aud` claim against `OBOT_OIDC_CLIENT_ID` and requires `email_verified: true`.

**Access control (required):**
```env
# Comma-separated list of OAuth client IDs allowed to perform token exchange
OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS=default:my-oauth-client

# Auto-create users on first exchange (default: true)
OBOT_EXTERNAL_IDP_AUTO_PROVISION=true
```

### Prerequisites

1. **Register an OAuth client** in Obot with `urn:ietf:params:oauth:grant-type:token-exchange` in its grant types
2. **Add the client** to `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS`
3. **Set the IdP client IDs** — the token's `aud` claim must match the configured client ID for the respective validator

### Token Exchange Request

```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<IdP_ID_token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&client_id=default:my-oauth-client
&client_secret=<client_secret>
```

Works identically for Google, Entra, and Dex tokens. The `iss` claim in the token determines which validator handles it.

### Response

```json
{
  "access_token": "<Obot-signed JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

The returned JWT is signed with EdDSA (Ed25519) and can be verified against Obot's JWKS at `GET /oauth/jwks.json`. It contains the user's Obot identity, email, and the originating auth provider name.

## User Identity

Both authentication paths share the same identity store. A user who logs in via Google browser auth and a service that exchanges a Google ID token for the same user will resolve to the **same Obot identity**, provided the `sub` claim matches.

This means:
- Users created through browser login can authenticate via token exchange (and vice versa if auto-provisioning is enabled)
- Permissions, project memberships, and audit logs are unified across both paths
- The `AuthProviderName` (e.g., `google-auth-provider`, `entra-auth-provider`, or the configured OIDC provider name) is stored on the identity record regardless of which path created it

## Architecture Comparison

```
Browser Login (single IdP):
  Browser --> /oauth2/start --> Auth Provider Daemon --> IdP --> callback --> Obot session

RFC 8693 Token Exchange (multi IdP, native):
  Service --[Google ID token]--> POST /oauth/token --> Google Validator --> Obot JWT
  Service --[Entra ID token]---> POST /oauth/token --> Entra Validator  --> Obot JWT
  Service --[Dex ID token]-----> POST /oauth/token --> OIDC Validator   --> Obot JWT

With Dex (only if browser multi-IdP is needed):
  Browser --> /oauth2/start --> Auth Provider Daemon --> Dex --> Google/Entra --> callback --> Obot session
```

The token exchange path bypasses the auth provider daemon entirely. Validation is done in-process using the IdP's public JWKS keys (fetched and cached automatically). No additional infrastructure is required.
