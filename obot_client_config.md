# Obot Client Integration Guide

This document is for engineering teams building first-party clients (`maistack-research`,
`langopen-cli`, `voice`, `amicable`, …) that consume MCP servers through the
Mayflower Obot deployment.

It tells you:

1. How to obtain an Obot session **silently** — no extra browser dance, reusing
   the user's existing Dex login (RFC 8693 token exchange).
2. How to call MCP servers through Obot using that session.
3. How to handle MCP servers whose tools require their **own** OAuth (the
   "mcp-dynamic-auth-endpoints" case), and how to make sure the user lands back
   on **your** host afterwards.

It assumes:

- The user is already authenticated to Dex (`https://id.data.mayflower.tech`)
  and your client holds a valid Dex ID token for them.
- Obot is reachable at `https://obot.data.mayflower.tech`.
- You have (or will register) an OAuth client at Obot whose Dex `aud` matches
  what you put in the ID token.

If any of those are not true, see *Pre-flight* at the end of this doc.

---

## 1. Silent session bootstrap (RFC 8693 token exchange)

This is the recommended way to get an Obot access token from your client.

### Endpoint

```
POST https://obot.data.mayflower.tech/oauth/token
Content-Type: application/x-www-form-urlencoded
```

### Request

| form field | value | notes |
|---|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 |
| `subject_token` | `<dex-issued ID token>` | The JWT your app already has |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` | **Important** — this is what routes the request to the external-IdP validator |
| `client_id` | `<namespace>:<obot-client-name>` | e.g. `default:oc1maistack-langserve`. Must be in Obot's `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` |
| `client_secret` | `<your secret>` | Required if your OAuth client was registered with `token_endpoint_auth_method=client_secret_post`; omit for `none` |

The Dex ID token must:

- be signed by `https://id.data.mayflower.tech`
- have `email_verified: true`
- carry an `aud` claim listing one of the values in Obot's
  `OBOT_OIDC_CLIENT_ID` (currently `maistack-research,langopen-cli` — talk to ops
  to add more)
- have an email under one of the `OBOT_OIDC_ALLOWED_DOMAINS` (currently
  `mayflower.de`)

### Response

```json
{
  "access_token": "obot.<opaque-jwt>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Use `access_token` as a `Bearer` token on subsequent Obot calls.

### Examples

#### Python

```python
import requests

dex_id_token = get_dex_id_token()  # whatever you do today

resp = requests.post(
    "https://obot.data.mayflower.tech/oauth/token",
    data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": dex_id_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
        "client_id": "default:oc1maistack-langserve",
        # "client_secret": "...",  # only if your client uses client_secret_post
    },
    timeout=10,
)
resp.raise_for_status()
obot_access_token = resp.json()["access_token"]
```

#### Node / TypeScript

```ts
const resp = await fetch("https://obot.data.mayflower.tech/oauth/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: dexIdToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
    client_id: "default:oc1maistack-langserve",
    // client_secret: "...",
  }),
});
if (!resp.ok) throw new Error(`obot token exchange failed: ${resp.status}`);
const { access_token } = await resp.json();
```

#### curl (for testing)

```bash
curl -sf -X POST https://obot.data.mayflower.tech/oauth/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d "subject_token=$DEX_ID_TOKEN" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d client_id=default:oc1maistack-langserve \
  | jq -r .access_token
```

### Common errors

| HTTP | `error` body | Likely cause |
|---|---|---|
| 400 | `unauthorized_client` | Your `client_id` is not in `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` |
| 400 | `invalid_grant` ("subject token validation failed") | Token signature/issuer/aud/email-verified/domain check failed; see Obot logs for the specific reason |
| 400 | "subject_token_type must be …" | You sent the wrong `subject_token_type`; double-check it is `…id_token` not `…jwt` |

---

## 2. Calling MCP servers with the Obot session

Once you have an Obot `access_token`, call MCP servers through Obot's gateway:

```
GET/POST https://obot.data.mayflower.tech/mcp-connect/<mcp_id>/...
Authorization: Bearer <access_token>
```

`<mcp_id>` is the ID of the MCP server you want to talk to. You'll get this from
Obot's catalog APIs or from your config.

If the MCP server doesn't itself require OAuth, that's all there is — you talk
JSON-RPC over the proxied connection.

If the MCP server **does** require OAuth (Slack, GitHub, Google Calendar,
anything in the dynamic-auth-endpoints family), Obot will tell you with a
`401 WWW-Authenticate` header pointing at the resource metadata. That's where
the next section comes in.

---

## 3. Per-client return URLs for MCP OAuth

When a downstream MCP server requires OAuth, the user has to consent in their
browser. Obot brokers that flow. After it completes, the user must land back
**on your host**, not on Obot's UI and not on some other client's host.

### How to ask Obot to redirect to your host

Append `?return_url=<your-host>/<your-callback-path>` to the MCP-OAuth entry
URL. There are three entry-point shapes; use the one your MCP server's runtime
dictates (Obot's `WWW-Authenticate` response will tell you which):

| MCP runtime | Entry URL pattern |
|---|---|
| Single-server | `https://obot.data.mayflower.tech/mcp-connect/<mcp_id>/auth?return_url=<your-url>` |
| Project-scoped | `https://obot.data.mayflower.tech/api/projects/<project_id>/mcp/<mcp_id>/auth?return_url=<your-url>` |
| Composite | `https://obot.data.mayflower.tech/auth/mcp/composite/<mcp_id>?return_url=<your-url>` |

Open this URL in a popup, an iframe, or a full-page redirect. The user will go
through Obot's session check + the downstream IdP login + Obot's callback, then
end up at the URL you provided.

### Example (TypeScript, popup style)

```ts
const returnURL = `${window.location.origin}/oauth-done`;
const url = new URL(`https://obot.data.mayflower.tech/mcp-connect/${mcpId}/auth`);
url.searchParams.set("return_url", returnURL);

const popup = window.open(url.toString(), "obot-oauth", "width=520,height=720");
// when the popup navigates back to /oauth-done it can postMessage to the opener
```

### The allowlist (what makes a return URL accepted)

Obot validates `return_url` against a comma-separated allowlist set on the
deployment (`OBOT_MCP_OAUTH_RETURN_URL_ALLOWLIST`). Currently:

```
https://maistack-research.data.mayflower.zone
https://maistack.data.mayflower.tech
https://voice.data.mayflower.tech         # placeholder — talk to ops once your real host is set
https://amicable.data.mayflower.tech      # placeholder — same
```

Matching rules:

- **scheme + host must match exactly** (case-insensitive).
- **path is treated as a prefix.** An allowlist entry of
  `https://maistack.data.mayflower.tech` accepts any path under that host;
  `https://maistack.data.mayflower.tech/oauth-done` only accepts that exact path
  (and, with a trailing slash, anything under it).

If your `return_url` doesn't match, Obot answers `400` with body
`return_url is not allowed`.

### What if you forget `return_url`?

The user lands on `{OBOT_SERVER_UI_HOSTNAME}/login_complete` — currently
`https://maistack-research.data.mayflower.zone/login_complete`. That's a generic
Obot page; your client won't know the OAuth dance is done. **Always pass
`return_url`** unless you genuinely want users on Obot's UI.

### Composite-server caveat

If the MCP server you target has `Spec.CompositeName != ""` (a composite that
proxies multiple component servers), Obot **ignores** `return_url` and falls
back to `OBOT_SERVER_UI_HOSTNAME/login_complete`. None of the current clients
look like they target composite servers, but if you find yourself in that
boat, talk to ops — there's a tracked stretch goal to add a per-client field on
the OAuth client CRD that bypasses this restriction.

---

## 4. Putting it together — full integration sequence

```
┌──────────┐                                    ┌──────────┐
│  Client  │                                    │   Obot   │
└────┬─────┘                                    └────┬─────┘
     │                                               │
     │  POST /oauth/token (id_token grant)           │
     ├──────────────────────────────────────────────►│
     │  ◄── access_token (Obot Bearer)               │
     │                                               │
     │  GET /mcp-connect/{mcp_id}/...                │
     │  Authorization: Bearer {access_token}         │
     ├──────────────────────────────────────────────►│
     │                                               │
     │  ◄── 401 WWW-Authenticate (mcp needs OAuth)   │
     │                                               │
     │  open browser to                              │
     │  /mcp-connect/{mcp_id}/auth                   │
     │     ?return_url=https://you.example/done      │
     │                                               │       (downstream IdP …)
     │                                               ├─────►
     │                                               │◄─────
     │  ◄── 302 to https://you.example/done          │
     │                                               │
     │  retry GET /mcp-connect/{mcp_id}/...          │
     ├──────────────────────────────────────────────►│
     │  ◄── 200 (now authorized end-to-end)          │
     │                                               │
```

---

## 5. Configuration reference (server side, for context)

You don't set any of these — ops does, in `data-cluster/obot/values.yaml`. They
are listed so you know what to ask for when you need a change.

| env var | what it controls | who owns adding new entries |
|---|---|---|
| `OBOT_OIDC_ISSUER` | Trusted Dex issuer for `id_token` grants | ops |
| `OBOT_OIDC_CLIENT_ID` | Comma-separated list of Dex `aud` claims accepted | ops — ask to add yours |
| `OBOT_OIDC_ALLOWED_DOMAINS` | Email-domain allowlist | ops |
| `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS` | Comma-separated `namespace:name` of OAuth clients allowed to use the `id_token` grant | ops — ask to add yours |
| `OBOT_EXTERNAL_IDP_AUTO_PROVISION` | If `true`, first contact creates the user automatically | ops |
| `OBOT_MCP_OAUTH_RETURN_URL_ALLOWLIST` | Comma-separated absolute URLs accepted as `return_url` | ops — ask to add yours |

---

## 6. Pre-flight checklist for a new client

When onboarding a new client (e.g. `voice` or `amicable`):

- [ ] **Dex side:** create an OIDC client in Dex with a known `client_id` (this
  becomes the `aud` of your ID tokens). For confidential clients, store the
  client secret somewhere safe.
- [ ] **Dex side:** confirm the client emits ID tokens with
  `email_verified: true` and an email at a domain in
  `OBOT_OIDC_ALLOWED_DOMAINS`.
- [ ] **Obot side (ops):** add your Dex `client_id` to `OBOT_OIDC_CLIENT_ID`.
- [ ] **Obot side (ops):** register an Obot OAuth client (via
  `POST /oauth/register` or via the admin UI). Note the `namespace:name`.
- [ ] **Obot side (ops):** add that `namespace:name` to
  `OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS`.
- [ ] **Obot side (ops):** add your hosts (each `scheme://host[/path]`) to
  `OBOT_MCP_OAUTH_RETURN_URL_ALLOWLIST`.
- [ ] **Client side:** implement section 1 (silent token exchange) and verify
  with `curl` you can swap a Dex ID token for an Obot access token.
- [ ] **Client side:** implement section 2 (calling MCP) and confirm a
  no-OAuth MCP server works end-to-end with the obtained access token.
- [ ] **Client side:** implement section 3 (`return_url`) and confirm an
  OAuth-requiring MCP server (e.g. Slack) lands the user back on your host
  with the OAuth complete.
- [ ] **Client side:** handle 401/403 on Obot calls by re-running the silent
  token exchange (the access_token is short-lived; do not cache it past
  `expires_in`).

---

## 7. Debugging tips

- **Obot pod logs** in namespace `obot`:
  `kubectl logs -n obot deploy/obot --tail=200 -f` will show every token
  exchange attempt with the validator name, email, and reason for rejection.
  Look for `External IdP token exchange:` lines.
- **Obot login traces:** the message
  `"Issued token-exchange response …"` confirms a successful exchange.
- **Allowlist troubleshooting:** if `return_url` is rejected, the response
  body will literally say so. Confirm the host matches case-insensitively
  and the scheme is `https://` (or `http://` if you're testing locally — that
  also has to be in the allowlist).
- **Audience troubleshooting:** if Dex tokens fail validation, run the token
  through [jwt.io](https://jwt.io) (paste the JWT, not the secret) and verify
  the `aud` and `iss` claims are exactly what Obot expects.

---

## 8. What this guide deliberately does **not** cover

- Long-lived API keys (issued via Obot's admin UI). Use those if your client
  has no upstream Dex session — but for first-party clients with Dex SSO,
  prefer the silent token exchange.
- The MCP protocol itself. Obot is a transparent gateway; the JSON-RPC body
  you send is the body the MCP server receives.
- Authoring Obot agents or workflows. That is admin/server-side work, not
  client integration.

If something is missing or wrong, edit this file in the
`rfc8693-external-idp-token-exchange` branch of `mayflower/obot` and open a PR.
