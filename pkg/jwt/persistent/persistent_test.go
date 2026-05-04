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

	req := httptest.NewRequest("GET", "https://obot.example.com/api/projects", nil)
	if service.ValidForRequest(tokenCtx, req) {
		t.Fatal("expected OAuth access token to reject API request")
	}

	tokenCtx.Audience = "https://other.example.com/mcp-connect/server1"
	req = httptest.NewRequest("GET", "https://obot.example.com/mcp-connect/server1", nil)
	if service.ValidForRequest(tokenCtx, req) {
		t.Fatal("expected OAuth access token to reject another origin")
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
