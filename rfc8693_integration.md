# RFC 8693 Token Exchange Integration Guide

This guide explains how to integrate an external chat application that uses Google or Microsoft Entra ID authentication with Obot as an MCP gateway, using RFC 8693 OAuth 2.0 Token Exchange.

## Overview

RFC 8693 (OAuth 2.0 Token Exchange) allows your chat system's backend to exchange external Identity Provider tokens (Google, Microsoft Entra ID) for Obot access tokens, enabling seamless single sign-on. Users authenticate once with their IdP in your chat application, and your backend propagates that authentication to Obot and the MCP servers it manages.

**Supported Identity Providers:**
- Google (ID tokens)
- Microsoft Entra ID (ID tokens)

```
┌──────────┐     ┌───────────────────┐     ┌─────────┐     ┌─────────────┐
│          │     │                   │     │         │     │             │
│  Browser │────▶│  Chat Backend     │────▶│  Obot   │────▶│ MCP Servers │
│          │     │  (token exchange) │     │         │     │             │
│          │     │                   │     │         │     │             │
└──────────┘     └───────────────────┘     └─────────┘     └─────────────┘
      │                   │                      │
      │ Google ID Token   │                      │
      │ ────────────────▶ │  RFC 8693 Exchange   │
      │                   │ ───────────────────▶ │
      │                   │                      │
      │                   │  Obot Access Token   │
      │                   │ ◀─────────────────── │
      │                   │                      │
      │ Session (cookie)  │  (stores token       │
      │ ◀──────────────── │   server-side)       │
```

The token exchange happens server-to-server. The browser never sees the Obot token.

## Prerequisites

1. **Identity Provider Client**: OAuth 2.0 client ID configured for your chat application (Google or Microsoft Entra ID)
2. **Obot Instance**: Running Obot with external IdP token exchange enabled
3. **Obot OAuth Client**: An OAuth client registered in Obot that is authorized for token exchange

## Obot Configuration

### Environment Variables Summary

| Variable | Purpose | Required | Default |
|----------|---------|----------|---------|
| `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` | Comma-separated OAuth client IDs allowed for token exchange | Yes | (none) |
| `OBOT_EXTERNAL_IDP_AUTO_PROVISION` | Allow creating new users via token exchange | No | `true` |
| `OBOT_GOOGLE_CLIENT_ID` | Google OAuth client ID for audience validation | For Google | - |
| `OBOT_GOOGLE_ALLOWED_DOMAINS` | Comma-separated allowed email domains | No | (all) |
| `OBOT_GOOGLE_ALLOWED_HDS` | Comma-separated allowed Google Workspace hosted domains | No | (all) |
| `OBOT_ENTRA_CLIENT_ID` | Azure AD application client ID | For Entra | - |
| `OBOT_ENTRA_TENANT_ID` | Azure AD tenant ID | No | `common` |
| `OBOT_ENTRA_ALLOWED_TENANTS` | Comma-separated allowed tenant IDs | No | (all) |
| `OBOT_ENTRA_ALLOWED_DOMAINS` | Comma-separated allowed email domains | No | (all) |

### 1. Configure Client Authorization (Required)

External IdP token exchange is disabled by default. You must explicitly configure which OAuth clients can use this feature:

```bash
# Format: namespace:client-name (comma-separated for multiple clients)
export OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS="default:my-chat-app,default:my-mobile-app"
```

**Security Note:** This is a critical security control. Only clients you trust should be allowed to exchange external IdP tokens for Obot tokens.

### 2. Configure Identity Providers

#### Google Configuration

```bash
# Required: Google OAuth client ID (must match the client ID used by your app)
export OBOT_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com

# Optional: Restrict to specific email domains
export OBOT_GOOGLE_ALLOWED_DOMAINS=example.com,corp.example.com

# Optional: Restrict to specific Google Workspace hosted domains
export OBOT_GOOGLE_ALLOWED_HDS=example.com
```

#### Microsoft Entra ID Configuration

```bash
# Required: Azure AD application client ID
export OBOT_ENTRA_CLIENT_ID=your-azure-app-client-id

# Optional: Specific tenant ID (default: "common" for multi-tenant)
export OBOT_ENTRA_TENANT_ID=your-tenant-id

# Optional: Restrict to specific Azure AD tenant IDs
export OBOT_ENTRA_ALLOWED_TENANTS=tenant-id-1,tenant-id-2

# Optional: Restrict to specific email domains
export OBOT_ENTRA_ALLOWED_DOMAINS=example.com,contoso.com
```

### 3. User Provisioning Controls

By default, Obot will automatically create user accounts when a valid external IdP token is exchanged:

```bash
# Default: true (users are auto-provisioned)
export OBOT_EXTERNAL_IDP_AUTO_PROVISION=true

# Set to false to require pre-provisioned users
export OBOT_EXTERNAL_IDP_AUTO_PROVISION=false
```

When auto-provisioning is disabled, token exchange will fail with `access_denied` for users who don't already have an Obot account.

### 4. Verify OAuth Discovery Endpoint

Obot exposes OAuth discovery at:

```
GET /.well-known/oauth-authorization-server
```

Response includes:
```json
{
  "issuer": "https://your-obot-instance.com",
  "token_endpoint": "https://your-obot-instance.com/oauth/token",
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:token-exchange"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ]
}
```

## Token Exchange Flow

### Step 1: User Authenticates with Google in Chat App

Your chat application authenticates users with Google OAuth and obtains a Google ID token. This is your standard Google Sign-In flow.

```javascript
// Example: Google Sign-In in your chat app
const googleUser = await googleAuth.signIn();
const googleIdToken = googleUser.getAuthResponse().id_token;
```

### Step 2: Exchange Google ID Token for Obot Access Token

Make a POST request to Obot's token endpoint with the RFC 8693 token exchange grant type:

```http
POST /oauth/token HTTP/1.1
Host: your-obot-instance.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=eyJhbGciOiJSUzI1NiIs...  (Google ID token)
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&resource=https://your-obot-instance.com
```

### Step 3: Receive Obot Access Token

Obot validates the Google ID token and returns an Obot access token:

```json
{
  "access_token": "obot_abc123:xyz789...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 604800
}
```

The access token is valid for 7 days.

### Step 4: Use Obot Access Token for MCP Requests

Include the Obot access token in subsequent requests to access MCP servers:

```http
GET /api/mcp/servers HTTP/1.1
Host: your-obot-instance.com
Authorization: Bearer obot_abc123:xyz789...
```

## Code Examples

All examples show server-side implementations where the token exchange happens in your backend.

### Node.js/TypeScript (Express)

```typescript
import express from 'express';

interface TokenExchangeResponse {
  access_token: string;
  issued_token_type: string;
  token_type: string;
  expires_in: number;
}

const OBOT_URL = process.env.OBOT_URL || 'https://your-obot-instance.com';

async function exchangeGoogleTokenForObot(
  googleIdToken: string
): Promise<TokenExchangeResponse> {
  const response = await fetch(`${OBOT_URL}/oauth/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
      subject_token: googleIdToken,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      resource: OBOT_URL,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Token exchange failed: ${error.error_description || error.error}`);
  }

  return response.json();
}

// Express route: receives Google ID token from browser, exchanges server-side
app.post('/api/auth/login', async (req, res) => {
  const { googleIdToken } = req.body;

  // Exchange Google token for Obot token (server-to-server)
  const obotToken = await exchangeGoogleTokenForObot(googleIdToken);

  // Store Obot token in server session (never sent to browser)
  req.session.obotToken = obotToken.access_token;
  req.session.obotTokenExpires = Date.now() + (obotToken.expires_in * 1000);

  res.json({ success: true });
});

// Proxy MCP requests through your backend
app.get('/api/mcp/*', async (req, res) => {
  const obotToken = req.session.obotToken;

  const response = await fetch(`${OBOT_URL}${req.path}`, {
    headers: { Authorization: `Bearer ${obotToken}` },
  });

  res.json(await response.json());
});
```

### Python (Flask)

```python
import os
import requests
from flask import Flask, request, session, jsonify
from typing import TypedDict

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

OBOT_URL = os.environ.get("OBOT_URL", "https://your-obot-instance.com")

class TokenExchangeResponse(TypedDict):
    access_token: str
    issued_token_type: str
    token_type: str
    expires_in: int

def exchange_google_token_for_obot(google_id_token: str) -> TokenExchangeResponse:
    """Exchange a Google ID token for an Obot access token (server-to-server)."""

    response = requests.post(
        f"{OBOT_URL}/oauth/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": google_id_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
            "resource": OBOT_URL,
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    response.raise_for_status()
    return response.json()

@app.route("/api/auth/login", methods=["POST"])
def login():
    """Receive Google ID token from browser, exchange server-side."""
    google_id_token = request.json["googleIdToken"]

    # Exchange Google token for Obot token (server-to-server)
    obot_token = exchange_google_token_for_obot(google_id_token)

    # Store in server session (never sent to browser)
    session["obot_token"] = obot_token["access_token"]
    session["obot_token_expires"] = obot_token["expires_in"]

    return jsonify({"success": True})

@app.route("/api/mcp/<path:path>")
def proxy_mcp(path: str):
    """Proxy MCP requests through backend using stored Obot token."""
    obot_token = session.get("obot_token")

    response = requests.get(
        f"{OBOT_URL}/api/mcp/{path}",
        headers={"Authorization": f"Bearer {obot_token}"},
    )

    return jsonify(response.json())
```

### Go (net/http)

```go
package main

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "os"
    "strings"
)

var obotURL = os.Getenv("OBOT_URL")

type TokenExchangeResponse struct {
    AccessToken     string `json:"access_token"`
    IssuedTokenType string `json:"issued_token_type"`
    TokenType       string `json:"token_type"`
    ExpiresIn       int    `json:"expires_in"`
}

// exchangeGoogleTokenForObot performs server-to-server token exchange
func exchangeGoogleTokenForObot(googleIDToken string) (*TokenExchangeResponse, error) {
    data := url.Values{
        "grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
        "subject_token":      {googleIDToken},
        "subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"},
        "resource":           {obotURL},
    }

    resp, err := http.Post(
        obotURL+"/oauth/token",
        "application/x-www-form-urlencoded",
        strings.NewReader(data.Encode()),
    )
    if err != nil {
        return nil, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("token exchange failed with status: %d", resp.StatusCode)
    }

    var result TokenExchangeResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, fmt.Errorf("failed to decode response: %w", err)
    }

    return &result, nil
}

// loginHandler receives Google ID token from browser, exchanges server-side
func loginHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        GoogleIDToken string `json:"googleIdToken"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    // Exchange Google token for Obot token (server-to-server)
    obotToken, err := exchangeGoogleTokenForObot(req.GoogleIDToken)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

    // Store in server session (use your session library)
    // session.Set("obot_token", obotToken.AccessToken)

    json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
```

### cURL

```bash
# Exchange Google ID token for Obot access token
curl -X POST "https://your-obot-instance.com/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${GOOGLE_ID_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "resource=https://your-obot-instance.com"
```

## Token Lifecycle Management

### Token Expiration

- **Obot Access Tokens**: Valid for 7 days (604800 seconds)
- **Google ID Tokens**: Typically valid for 1 hour

### Server-Side Token Refresh Strategy

Your backend should handle token refresh transparently. When a user's Obot token expires:

1. Check if user's Google session is still valid
2. If valid, get a fresh Google ID token and perform a new token exchange
3. If Google session expired, return 401 to trigger re-authentication in browser

```typescript
// Server-side token manager (e.g., in Express middleware)
async function ensureValidObotToken(req: Request): Promise<string> {
  const session = req.session;

  // Check if Obot token is expired or about to expire (5 min buffer)
  if (!session.obotToken || Date.now() >= session.obotTokenExpires - 300000) {
    // Get fresh Google ID token from your auth system
    // This depends on your Google auth implementation
    const googleIdToken = await getFreshGoogleIdToken(session.userId);

    if (!googleIdToken) {
      throw new AuthError('Google session expired, re-authentication required');
    }

    // Perform new token exchange
    const response = await exchangeGoogleTokenForObot(googleIdToken);

    session.obotToken = response.access_token;
    session.obotTokenExpires = Date.now() + (response.expires_in * 1000);
  }

  return session.obotToken;
}

// Use in middleware
app.use('/api/mcp/*', async (req, res, next) => {
  try {
    req.obotToken = await ensureValidObotToken(req);
    next();
  } catch (err) {
    if (err instanceof AuthError) {
      res.status(401).json({ error: 'authentication_required' });
    } else {
      next(err);
    }
  }
});
```

## User Identity Mapping

### Google ID Tokens

When Obot receives a Google ID token, it extracts the following claims:

| Google Claim | Obot Field | Description |
|--------------|------------|-------------|
| `sub` | `provider_user_id` | Unique Google user identifier |
| `email` | `email` | User's email address |
| `email_verified` | (validated) | Must be `true` for token acceptance |
| `name` | `name` | User's display name |
| `picture` | `icon_url` | User's profile picture URL |
| `hd` | (validated) | Google Workspace hosted domain (if configured) |

**Requirements:**
1. `email_verified: true` in the token
2. A valid `email` claim
3. `aud` matches `OBOT_GOOGLE_CLIENT_ID`
4. If `OBOT_GOOGLE_ALLOWED_DOMAINS` is set, email domain must be in the list
5. If `OBOT_GOOGLE_ALLOWED_HDS` is set, `hd` claim must be present and in the list

### Microsoft Entra ID Tokens

When Obot receives a Microsoft Entra ID token, it extracts the following claims:

| Entra ID Claim | Obot Field | Description |
|----------------|------------|-------------|
| `oid` | `provider_user_id` | Object ID (stable user identifier within tenant) |
| `email`, `preferred_username`, or `upn` | `email` | User's email (tries multiple claims) |
| `name` | `name` | User's display name |
| `tid` | (validated) | Tenant ID (if tenant restrictions configured) |

**Note:** Obot uses `oid` (Object ID) rather than `sub` for Entra ID tokens because `sub` is pairwise and changes per-application, while `oid` is stable within the tenant.

**Requirements:**
1. `aud` matches `OBOT_ENTRA_CLIENT_ID`
2. Valid signature (verified against Microsoft's JWKS)
3. Token not expired
4. If `OBOT_ENTRA_ALLOWED_TENANTS` is set, `tid` must be in the list
5. If `OBOT_ENTRA_ALLOWED_DOMAINS` is set, email domain must be in the list

## Error Handling

### Common Error Responses

**Unauthorized Client**
```json
{
  "error": "unauthorized_client",
  "error_description": "client is not authorized for external IdP token exchange"
}
```
Cause: The OAuth client is not in the `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` allowlist. Add your client ID (format: `namespace:client-name`) to the allowlist.

**Invalid Token**
```json
{
  "error": "invalid_grant",
  "error_description": "subject token validation failed"
}
```
Cause: The IdP token is invalid, expired, malformed, or has the wrong audience. Possible reasons:
- Token signature verification failed
- Token has expired
- `aud` claim doesn't match the configured client ID
- For Google: `email_verified` is false
- For Entra ID: tenant or domain not in allowlist

**User Not Provisioned**
```json
{
  "error": "access_denied",
  "error_description": "user not registered"
}
```
Cause: Auto-provisioning is disabled (`OBOT_EXTERNAL_IDP_AUTO_PROVISION=false`) and the user doesn't have an existing Obot account. Either enable auto-provisioning or pre-create the user in Obot.

**Unsupported Issuer**
```json
{
  "error": "invalid_grant",
  "error_description": "subject token validation failed"
}
```
Cause: The token's issuer is not recognized. Obot currently supports:
- Google: `https://accounts.google.com`
- Microsoft Entra ID: `https://login.microsoftonline.com/*` and `https://sts.windows.net/*`

**Domain Not Allowed**
```json
{
  "error": "invalid_grant",
  "error_description": "subject token validation failed"
}
```
Cause: The user's email domain is not in the configured allowlist (`OBOT_GOOGLE_ALLOWED_DOMAINS` or `OBOT_ENTRA_ALLOWED_DOMAINS`).

**Unsupported Grant Type**
```json
{
  "error": "unsupported_grant_type",
  "error_description": "grant_type must be one of: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:token-exchange"
}
```
Cause: Wrong `grant_type` parameter.

**Internal Server Error**
```json
{
  "error": "server_error",
  "error_description": "internal error processing request"
}
```
Cause: An unexpected internal error occurred. Check the Obot server logs for details.

### Handling Errors in Backend Code

```typescript
// Server-side error handling
async function handleTokenExchange(googleIdToken: string, res: Response): Promise<string | null> {
  try {
    const response = await exchangeGoogleTokenForObot(googleIdToken);
    return response.access_token;
  } catch (error) {
    if (error.message.includes('invalid_grant')) {
      // Token validation failed - tell browser to re-authenticate
      res.status(401).json({
        error: 'authentication_required',
        message: 'Google token invalid or expired, please sign in again'
      });
      return null;
    }
    throw error;
  }
}
```

## Security Considerations

### 1. Token Storage

Since token exchange happens server-side, Obot tokens should never reach the browser:

- Store Obot tokens in server-side sessions (Redis, database, memory)
- Use httpOnly session cookies for browser↔backend communication
- Never include Obot tokens in API responses to the browser
- Clear tokens from server session on user logout

### 2. HTTPS Required

All token exchange requests must use HTTPS in production.

### 3. Token Validation

Obot validates Google ID tokens by:
- Verifying the signature using Google's JWKS (JSON Web Key Set)
- Checking token expiration
- Validating the audience matches the configured client ID
- Ensuring email is verified

### 4. Same Google Client ID

For security, Obot must be configured with the same Google Client ID that your chat application uses. This ensures that tokens issued for your application cannot be replayed against other applications.

## Architecture

The token exchange should be performed server-side in your chat backend. This keeps the Obot token secure and allows your backend to manage token lifecycle.

```
┌──────────┐     ┌──────────────┐     ┌──────────┐     ┌─────────────┐
│  Browser │────▶│ Chat Backend │────▶│   Obot   │────▶│ MCP Servers │
└──────────┘     └──────────────┘     └──────────┘     └─────────────┘
     │                  │                   │
     │ Google ID Token  │                   │
     │ ───────────────▶ │                   │
     │                  │ Token Exchange    │
     │                  │ ────────────────▶ │
     │                  │                   │
     │                  │ Obot Token        │
     │                  │ ◀──────────────── │
     │                  │                   │
     │ Session Cookie   │  (token stored    │
     │ ◀─────────────── │   server-side)    │
```

**Why server-side:**
- Obot token never exposed to browser (not vulnerable to XSS)
- Backend manages token refresh transparently
- No CORS configuration needed on Obot
- Tokens stored in secure server session, not browser storage

## Testing the Integration

### 1. Get a Google ID Token

Use the Google OAuth Playground or your app to get a valid ID token:

```bash
# If using gcloud CLI
gcloud auth print-identity-token
```

### 2. Test Token Exchange

```bash
export GOOGLE_ID_TOKEN="eyJhbGciOiJSUzI1NiIs..."
export OBOT_URL="https://your-obot-instance.com"

curl -v -X POST "${OBOT_URL}/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${GOOGLE_ID_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:id_token" \
  -d "resource=${OBOT_URL}"
```

### 3. Verify Access

```bash
export OBOT_TOKEN="obot_abc123:xyz789..."

curl -H "Authorization: Bearer ${OBOT_TOKEN}" \
  "${OBOT_URL}/api/me"
```

## Troubleshooting

### Token Exchange Returns "unauthorized_client"

1. Check that `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` is configured
2. Verify your client ID is in the allowlist (format: `namespace:client-name`)
3. Ensure the OAuth client exists in Obot

### Token Exchange Returns "invalid_grant"

1. Verify the correct client ID is configured (`OBOT_GOOGLE_CLIENT_ID` or `OBOT_ENTRA_CLIENT_ID`)
2. Check that the IdP token is not expired
3. Ensure the token's audience matches the configured client ID
4. If domain restrictions are configured, verify the user's email domain is allowed
5. For Google: Check that `email_verified` is `true`
6. For Entra ID: Check that the tenant is allowed (if tenant restrictions are set)

### Token Exchange Returns "access_denied"

1. If auto-provisioning is disabled (`OBOT_EXTERNAL_IDP_AUTO_PROVISION=false`), the user must already exist in Obot
2. Pre-create the user in Obot or enable auto-provisioning

### User Not Created in Obot

1. Verify `email_verified` is `true` in Google tokens
2. Check that the `email` claim is present
3. Ensure auto-provisioning is enabled (`OBOT_EXTERNAL_IDP_AUTO_PROVISION=true`)

### Debug Token Contents

Decode a JWT (Google or Entra ID) to inspect claims:

```bash
# Decode JWT payload (base64)
echo "${TOKEN}" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
```

**Expected Google token claims:**
```json
{
  "iss": "https://accounts.google.com",
  "aud": "your-client-id.apps.googleusercontent.com",
  "sub": "123456789",
  "email": "user@example.com",
  "email_verified": true,
  "name": "User Name",
  "picture": "https://...",
  "hd": "example.com",
  "exp": 1234567890
}
```

**Expected Entra ID token claims:**
```json
{
  "iss": "https://login.microsoftonline.com/{tenant}/v2.0",
  "aud": "your-azure-app-client-id",
  "sub": "pairwise-subject-id",
  "oid": "object-id-stable",
  "tid": "tenant-id",
  "email": "user@example.com",
  "preferred_username": "user@example.com",
  "name": "User Name",
  "exp": 1234567890
}
```

### Check Which Validators Are Registered

The Obot server logs will show which validators are registered at startup:

```
INFO Registered external IdP validator: google
INFO Registered external IdP validator: entra
```

If a validator is not registered, check that the required environment variable is set (e.g., `OBOT_GOOGLE_CLIENT_ID` or `OBOT_ENTRA_CLIENT_ID`).

## Security Best Practices

### 1. Always Configure Client Authorization

Never deploy with an empty `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS`. This is a critical security control that prevents unauthorized clients from exchanging tokens.

### 2. Use Domain Restrictions in Production

For enterprise deployments, configure domain restrictions to limit which email domains can create accounts:

```bash
# Google: Only allow users from your organization
export OBOT_GOOGLE_ALLOWED_DOMAINS=yourcompany.com
export OBOT_GOOGLE_ALLOWED_HDS=yourcompany.com

# Entra ID: Only allow specific tenants
export OBOT_ENTRA_ALLOWED_TENANTS=your-tenant-id
```

### 3. Consider Disabling Auto-Provisioning

For high-security environments, disable auto-provisioning and pre-create user accounts:

```bash
export OBOT_EXTERNAL_IDP_AUTO_PROVISION=false
```

This ensures only pre-approved users can access Obot through token exchange.

### 4. Keep Tokens Server-Side

Always perform token exchange in your backend. Never expose Obot tokens to the browser:

- Store Obot tokens in server-side sessions only
- Use httpOnly cookies for browser↔backend session management
- Never return Obot tokens in API responses to the browser

### 5. Monitor Token Exchange Activity

Review Obot server logs regularly for:
- Failed token exchanges (may indicate attacks or misconfigurations)
- Unexpected issuers or domains
- High volumes of token exchanges from specific clients

## References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [Google Identity - ID Tokens](https://developers.google.com/identity/protocols/oauth2/openid-connect)
- [Microsoft Identity Platform - ID Tokens](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens)
- [Microsoft Identity Platform - Token Validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-tokens)
- [Obot MCP Gateway Documentation](https://docs.obot.ai/)
