package oauth

import (
	"testing"

	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
)

func TestCompletionRedirectValidatorValidate(t *testing.T) {
	validator, err := newCompletionRedirectValidator([]string{
		"https://maistack.example.com",
		"https://voicebot.example.com/obot/callback",
		"http://localhost:3000",
	})
	if err != nil {
		t.Fatalf("newCompletionRedirectValidator() error = %v", err)
	}

	tests := []struct {
		name      string
		raw       string
		want      string
		wantError bool
	}{
		{
			name: "empty is allowed",
			raw:  "",
			want: "",
		},
		{
			name: "origin allowlist matches deeper path",
			raw:  "https://maistack.example.com/app/obot?thread=123",
			want: "https://maistack.example.com/app/obot?thread=123",
		},
		{
			name: "path allowlist matches nested path",
			raw:  "https://voicebot.example.com/obot/callback/finish",
			want: "https://voicebot.example.com/obot/callback/finish",
		},
		{
			name:      "path allowlist rejects sibling path",
			raw:       "https://voicebot.example.com/obot/callback-other",
			wantError: true,
		},
		{
			name: "localhost is allowed when configured",
			raw:  "http://localhost:3000/obot/oauth-complete",
			want: "http://localhost:3000/obot/oauth-complete",
		},
		{
			name:      "relative URL is rejected",
			raw:       "/oauth-complete",
			wantError: true,
		},
		{
			name:      "disallowed host is rejected",
			raw:       "https://evil.example.com/app",
			wantError: true,
		},
		{
			name:      "host prefix confusion is rejected",
			raw:       "https://maistack.example.com.evil.com/app",
			wantError: true,
		},
		{
			name:      "unsupported scheme is rejected",
			raw:       "ftp://maistack.example.com/app",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validator.Validate(tt.raw)
			if tt.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("Validate() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewCompletionRedirectValidatorRejectsInvalidAllowlist(t *testing.T) {
	if _, err := newCompletionRedirectValidator([]string{"not-a-url"}); err == nil {
		t.Fatal("expected error for invalid allowlist entry")
	}
}

func TestAppendReturnURL(t *testing.T) {
	tests := []struct {
		name      string
		rawURL    string
		returnURL string
		want      string
	}{
		{
			name:      "adds return_url to empty query",
			rawURL:    "https://obot.example.com/auth/mcp/composite/server1",
			returnURL: "https://maistack.example.com/app",
			want:      "https://obot.example.com/auth/mcp/composite/server1?return_url=https%3A%2F%2Fmaistack.example.com%2Fapp",
		},
		{
			name:      "preserves existing query params",
			rawURL:    "https://obot.example.com/auth/mcp/composite/server1?oauth_auth_request=req-123",
			returnURL: "https://voicebot.example.com/app",
			want:      "https://obot.example.com/auth/mcp/composite/server1?oauth_auth_request=req-123&return_url=https%3A%2F%2Fvoicebot.example.com%2Fapp",
		},
		{
			name:      "empty return_url leaves URL unchanged",
			rawURL:    "https://obot.example.com/auth/mcp/composite/server1",
			returnURL: "",
			want:      "https://obot.example.com/auth/mcp/composite/server1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := appendReturnURL(tt.rawURL, tt.returnURL); got != tt.want {
				t.Fatalf("appendReturnURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUIOAuthCompletionRedirect(t *testing.T) {
	defaultRedirect := "https://obot.example.com/login_complete"
	storedRedirect := "https://maistack.example.com/app"

	tests := []struct {
		name       string
		server     v1.MCPServer
		completion string
		want       string
	}{
		{
			name:       "non composite uses stored redirect",
			server:     v1.MCPServer{},
			completion: storedRedirect,
			want:       storedRedirect,
		},
		{
			name:       "non composite falls back to default",
			server:     v1.MCPServer{},
			completion: "",
			want:       defaultRedirect,
		},
		{
			name: "composite component always uses default",
			server: v1.MCPServer{
				Spec: v1.MCPServerSpec{
					CompositeName: "composite-1",
				},
			},
			completion: storedRedirect,
			want:       defaultRedirect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := uiOAuthCompletionRedirect(defaultRedirect, tt.completion, tt.server); got != tt.want {
				t.Fatalf("uiOAuthCompletionRedirect() = %q, want %q", got, tt.want)
			}
		})
	}
}
