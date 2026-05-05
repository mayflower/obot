---
title: MCP Registry
---

# MCP Registry

The MCP Registry is a central place to list and discover MCP servers. It provides a curated collection of servers available to users based on their access permissions.

## Registry Concepts

### Server Sources

MCP server definitions can come from:

- **Official Obot repository**: The default set from [obot-platform/mcp-catalog](https://github.com/obot-platform/mcp-catalog)
- **Custom Git repositories**: Your own repositories containing server definitions (see [MCP Server GitOps](/configuration/mcp-server-gitops/))
- **Direct entry**: Servers added manually through the UI

### Server Definitions

Each server in the registry includes:

- **Name and Description**: Human-readable identification
- **Runtime Configuration**: How to run the server (npx, uvx, containerized, or remote)
- **Environment Variables**: Required and optional configuration
- **Tool Preview**: Description of available tools
- **Icon and Metadata**: For display in the UI

### Access Control

Administrators and Power Users+ control which servers are visible to which users by assigning servers to registries and granting users access to those registries.

## MCP Registry API

Obot implements the [MCP Registry specification](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/generic-registry-api.md), enabling MCP clients to programmatically discover available servers.

The registry API is exposed under `/v0.1`. Its primary discovery endpoint is `/v0.1/servers`, with version details available under `/v0.1/servers/{serverName}/versions`.

When registry authentication is disabled, the registry returns the servers granted to all users. When `OBOT_SERVER_ENABLE_REGISTRY_AUTH=true`, the registry returns the servers visible to the authenticated user. External applications that already authenticate users with an IdP can use Obot's RFC 8693 token exchange to exchange the user's external ID token for a registry-scoped bearer token. That token is valid only for read-only Registry API requests and is separate from the MCP Gateway token used for `/mcp-connect`.

## Learn More

- [MCP Registries](/functionality/mcp-registries/) - Managing registries, API details, and contributing servers
