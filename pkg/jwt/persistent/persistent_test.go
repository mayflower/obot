package persistent

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenServiceValidForRequestOAuthAccess(t *testing.T) {
	service := &TokenService{serverURL: "https://obot.example.com"}
	tokenCtx := &TokenContext{
		Audience:  "https://obot.example.com/mcp-connect/server1",
		ExpiresAt: time.Now().Add(time.Minute),
		TokenType: TokenTypeOAuthAccess,
	}

	for _, path := range []string{"/mcp-connect/server1", "/mcp-connect/server1/sse"} {
		req := httptest.NewRequest("GET", "https://obot.example.com"+path, nil)
		if !service.ValidForRequest(tokenCtx, req) {
			t.Fatalf("expected OAuth access token to allow %s", path)
		}
	}

	req := httptest.NewRequest("GET", "https://obot.example.com/mcp-connect/server2", nil)
	if service.ValidForRequest(tokenCtx, req) {
		t.Fatal("expected single-server OAuth access token to reject another MCP server")
	}

	req = httptest.NewRequest("GET", "https://obot.example.com/api/projects", nil)
	if service.ValidForRequest(tokenCtx, req) {
		t.Fatal("expected OAuth access token to reject API request")
	}

	tokenCtx.Audience = "https://other.example.com/mcp-connect/server1"
	req = httptest.NewRequest("GET", "https://obot.example.com/mcp-connect/server1", nil)
	if service.ValidForRequest(tokenCtx, req) {
		t.Fatal("expected OAuth access token to reject another origin")
	}
}

func TestTokenServiceValidForRequestOAuthAccessGatewayScoped(t *testing.T) {
	service := &TokenService{serverURL: "https://obot.example.com"}
	tokenCtx := &TokenContext{
		Audience:  "https://obot.example.com/mcp-connect",
		ExpiresAt: time.Now().Add(time.Minute),
		TokenType: TokenTypeOAuthAccess,
	}

	for _, path := range []string{"/mcp-connect/server1", "/mcp-connect/server2/sse"} {
		req := httptest.NewRequest("GET", "https://obot.example.com"+path, nil)
		if !service.ValidForRequest(tokenCtx, req) {
			t.Fatalf("expected gateway-scoped OAuth access token to allow %s", path)
		}
	}

	req := httptest.NewRequest("GET", "https://obot.example.com/api/projects", nil)
	if service.ValidForRequest(tokenCtx, req) {
		t.Fatal("expected gateway-scoped OAuth access token to reject API request")
	}

	req = httptest.NewRequest("GET", "https://obot.example.com/v0.1/servers", nil)
	if service.ValidForRequest(tokenCtx, req) {
		t.Fatal("expected gateway-scoped OAuth access token to reject registry request")
	}
}

func TestTokenServiceValidForRequestOAuthAccessRegistryScoped(t *testing.T) {
	service := &TokenService{serverURL: "https://obot.example.com"}

	for _, audience := range []string{
		"https://obot.example.com",
		"https://obot.example.com/v0.1",
		"https://obot.example.com/v0.1/servers",
	} {
		tokenCtx := &TokenContext{
			Audience:  audience,
			ExpiresAt: time.Now().Add(time.Minute),
			TokenType: TokenTypeOAuthAccess,
		}

		allowedPaths := []string{"/v0.1/servers", "/v0.1/servers/server1/versions"}
		if audience != "https://obot.example.com/v0.1/servers" {
			allowedPaths = append([]string{"/v0.1"}, allowedPaths...)
		}
		for _, path := range allowedPaths {
			req := httptest.NewRequest("GET", "https://obot.example.com"+path, nil)
			if !service.ValidForRequest(tokenCtx, req) {
				t.Fatalf("expected registry-scoped OAuth access token %q to allow %s", audience, path)
			}
		}

		req := httptest.NewRequest("POST", "https://obot.example.com/v0.1/servers", nil)
		if service.ValidForRequest(tokenCtx, req) {
			t.Fatalf("expected registry-scoped OAuth access token %q to reject write method", audience)
		}

		req = httptest.NewRequest("GET", "https://obot.example.com/api/mcp-servers", nil)
		if service.ValidForRequest(tokenCtx, req) {
			t.Fatalf("expected registry-scoped OAuth access token %q to reject API request", audience)
		}

		req = httptest.NewRequest("GET", "https://obot.example.com/mcp-connect/server1", nil)
		if service.ValidForRequest(tokenCtx, req) {
			t.Fatalf("expected registry-scoped OAuth access token %q to reject MCP gateway request", audience)
		}
	}

	tokenCtx := &TokenContext{
		Audience:  "https://other.example.com",
		ExpiresAt: time.Now().Add(time.Minute),
		TokenType: TokenTypeOAuthAccess,
	}
	req := httptest.NewRequest("GET", "https://obot.example.com/v0.1/servers", nil)
	if service.ValidForRequest(tokenCtx, req) {
		t.Fatal("expected registry-scoped OAuth access token to reject another origin")
	}
}

func TestTokenServiceValidForRequestMCPProxy(t *testing.T) {
	service := &TokenService{serverURL: "https://obot.example.com"}
	req := httptest.NewRequest("GET", "https://obot.example.com/mcp-connect/server1", nil)

	if service.ValidForRequest(&TokenContext{
		Audience:  "https://obot.example.com/mcp-connect/server1",
		TokenType: TokenTypeMCPProxy,
	}, req) {
		t.Fatal("expected MCP proxy token to be rejected by API auth")
	}
}

func TestTokenServiceValidForRequestGatewayAPI(t *testing.T) {
	service := &TokenService{serverURL: "https://obot.example.com"}
	req := httptest.NewRequest("GET", "https://obot.example.com/api/projects", nil)

	if !service.ValidForRequest(&TokenContext{
		Audience:  "https://obot.example.com",
		TokenType: TokenTypeGatewayAPI,
	}, req) {
		t.Fatal("expected gateway API token for this origin to be accepted")
	}

	if service.ValidForRequest(&TokenContext{
		Audience:  "https://other.example.com",
		TokenType: TokenTypeGatewayAPI,
	}, req) {
		t.Fatal("expected gateway API token for another origin to be rejected")
	}
}
