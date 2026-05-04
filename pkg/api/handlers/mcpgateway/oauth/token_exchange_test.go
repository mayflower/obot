package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// TestExtractIssuerFromJWT tests the JWT issuer extraction for routing purposes.
func TestExtractIssuerFromJWT(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		wantIssuer  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid Google token",
			token:      createTestJWT(t, map[string]interface{}{"iss": "https://accounts.google.com", "sub": "123"}),
			wantIssuer: "https://accounts.google.com",
		},
		{
			name:       "valid Entra ID token",
			token:      createTestJWT(t, map[string]interface{}{"iss": "https://login.microsoftonline.com/tenant-id/v2.0", "sub": "123"}),
			wantIssuer: "https://login.microsoftonline.com/tenant-id/v2.0",
		},
		{
			name:        "missing issuer claim",
			token:       createTestJWT(t, map[string]interface{}{"sub": "123"}),
			wantErr:     true,
			errContains: "missing issuer claim",
		},
		{
			name:        "invalid JWT - only 2 parts",
			token:       "header.payload",
			wantErr:     true,
			errContains: "invalid JWT",
		},
		{
			name:        "invalid JWT - 4 parts",
			token:       "a.b.c.d",
			wantErr:     true,
			errContains: "invalid JWT",
		},
		{
			name:        "invalid base64 payload",
			token:       "header.!!!invalid!!!.signature",
			wantErr:     true,
			errContains: "failed to decode",
		},
		{
			name:        "invalid JSON payload",
			token:       "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature",
			wantErr:     true,
			errContains: "failed to parse",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := extractIssuerFromJWT(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errContains)
					return
				}
				if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if issuer != tt.wantIssuer {
				t.Errorf("got issuer %q, want %q", issuer, tt.wantIssuer)
			}
		})
	}
}

// TestExternalIdPConfigClientAuthorization tests the client authorization logic.
func TestExternalIdPConfigClientAuthorization(t *testing.T) {
	tests := []struct {
		name           string
		allowedClients []string
		clientID       string
		want           bool
	}{
		{
			name:           "client in allowlist",
			allowedClients: []string{"default:my-app", "default:other-app"},
			clientID:       "default:my-app",
			want:           true,
		},
		{
			name:           "client not in allowlist",
			allowedClients: []string{"default:my-app", "default:other-app"},
			clientID:       "default:unknown-app",
			want:           false,
		},
		{
			name:           "empty allowlist denies all",
			allowedClients: []string{},
			clientID:       "default:my-app",
			want:           false,
		},
		{
			name:           "nil allowlist denies all",
			allowedClients: nil,
			clientID:       "default:my-app",
			want:           false,
		},
		{
			name:           "exact match required",
			allowedClients: []string{"default:my-app"},
			clientID:       "default:my-app-extended",
			want:           false,
		},
		{
			name:           "case sensitive",
			allowedClients: []string{"default:my-app"},
			clientID:       "default:My-App",
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ExternalIdPConfig{
				AllowedClientIDs: tt.allowedClients,
			}
			got := config.IsClientAllowed(tt.clientID)
			if got != tt.want {
				t.Errorf("IsClientAllowed(%q) = %v, want %v", tt.clientID, got, tt.want)
			}
		})
	}
}

func TestExternalIdPConfigDefaultsFailClosed(t *testing.T) {
	config := NewExternalIdPConfig()
	if config.AutoProvision {
		t.Fatal("expected external IdP auto-provisioning to default to disabled")
	}
	if config.IsClientAllowed("default:client") {
		t.Fatal("expected external IdP exchange to deny all clients without an allowlist")
	}
}

func TestGoogleIdPValidatorRequiresDomainPolicy(t *testing.T) {
	t.Setenv("OBOT_GOOGLE_CLIENT_ID", "google-client")
	if _, err := NewGoogleIdPValidator(); err == nil {
		t.Fatal("expected Google validator to require a domain policy")
	}

	t.Setenv("OBOT_GOOGLE_ALLOWED_DOMAINS", "example.com")
	if _, err := NewGoogleIdPValidator(); err != nil {
		t.Fatalf("expected Google validator with allowed domain, got %v", err)
	}
}

func TestGoogleIdPValidatorAllowsExplicitDomainOverride(t *testing.T) {
	t.Setenv("OBOT_GOOGLE_CLIENT_ID", "google-client")
	t.Setenv("OBOT_GOOGLE_ALLOW_ALL_DOMAINS", "true")

	if _, err := NewGoogleIdPValidator(); err != nil {
		t.Fatalf("expected Google validator with explicit allow-all override, got %v", err)
	}
}

func TestOIDCIdPValidatorRequiresDomainPolicy(t *testing.T) {
	t.Setenv("OBOT_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("OBOT_OIDC_CLIENT_ID", "oidc-client")
	if _, err := NewOIDCIdPValidator(); err == nil {
		t.Fatal("expected OIDC validator to require a domain policy")
	}

	t.Setenv("OBOT_OIDC_ALLOWED_DOMAINS", "example.com")
	if _, err := NewOIDCIdPValidator(); err != nil {
		t.Fatalf("expected OIDC validator with allowed domain, got %v", err)
	}
}

func TestOIDCIdPValidatorAllowsExplicitDomainOverride(t *testing.T) {
	t.Setenv("OBOT_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("OBOT_OIDC_CLIENT_ID", "oidc-client")
	t.Setenv("OBOT_OIDC_ALLOW_ALL_DOMAINS", "true")

	if _, err := NewOIDCIdPValidator(); err != nil {
		t.Fatalf("expected OIDC validator with explicit allow-all override, got %v", err)
	}
}

func TestEntraIdPValidatorRequiresTenantPolicy(t *testing.T) {
	t.Setenv("OBOT_ENTRA_CLIENT_ID", "entra-client")
	if _, err := NewEntraIdPValidator(); err == nil {
		t.Fatal("expected Entra validator to require a tenant policy")
	}

	t.Setenv("OBOT_ENTRA_TENANT_ID", "tenant-id")
	if _, err := NewEntraIdPValidator(); err != nil {
		t.Fatalf("expected Entra validator with tenant ID, got %v", err)
	}
}

func TestEntraIdPValidatorAllowsExplicitTenantOverride(t *testing.T) {
	t.Setenv("OBOT_ENTRA_CLIENT_ID", "entra-client")
	t.Setenv("OBOT_ENTRA_ALLOW_ANY_TENANT", "true")

	if _, err := NewEntraIdPValidator(); err != nil {
		t.Fatalf("expected Entra validator with explicit allow-any override, got %v", err)
	}
}

func TestExternalTokenExchangeAudience(t *testing.T) {
	h := &handler{baseURL: "https://obot.example.com"}
	mcpID, audience, err := h.externalTokenExchangeAudience("https://obot.example.com/mcp-connect/server1/sse")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mcpID != "server1" {
		t.Fatalf("expected mcpID server1, got %q", mcpID)
	}
	if audience != "https://obot.example.com/mcp-connect/server1" {
		t.Fatalf("unexpected audience %q", audience)
	}

	for _, resource := range []string{
		"https://other.example.com/mcp-connect/server1",
		"https://obot.example.com/api/projects",
		"/mcp-connect/server1",
	} {
		if _, _, err := h.externalTokenExchangeAudience(resource); err == nil {
			t.Fatalf("expected %q to be rejected", resource)
		}
	}
}

// TestExternalIdPRegistryIssuerRouting tests the registry's issuer-based routing.
func TestExternalIdPRegistryIssuerRouting(t *testing.T) {
	registry := &ExternalIdPRegistry{
		validators: make(map[string]ExternalIdPValidator),
	}

	// Register mock validators
	googleValidator := &mockValidator{
		name:     "google",
		patterns: []string{"https://accounts.google.com", "accounts.google.com"},
	}
	entraValidator := &mockValidator{
		name:     "entra",
		patterns: []string{"https://login.microsoftonline.com/", "https://sts.windows.net/"},
	}

	registry.Register(googleValidator)
	registry.Register(entraValidator)

	tests := []struct {
		name         string
		issuer       string
		wantProvider string
		wantFound    bool
	}{
		{
			name:         "routes to Google for exact match",
			issuer:       "https://accounts.google.com",
			wantProvider: "google",
			wantFound:    true,
		},
		{
			name:         "routes to Google for alternative issuer",
			issuer:       "accounts.google.com",
			wantProvider: "google",
			wantFound:    true,
		},
		{
			name:         "routes to Entra for prefix match",
			issuer:       "https://login.microsoftonline.com/tenant-123/v2.0",
			wantProvider: "entra",
			wantFound:    true,
		},
		{
			name:         "routes to Entra for sts.windows.net",
			issuer:       "https://sts.windows.net/tenant-456/",
			wantProvider: "entra",
			wantFound:    true,
		},
		{
			name:         "unknown issuer not found",
			issuer:       "https://unknown-issuer.com",
			wantProvider: "",
			wantFound:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := registry.findValidatorByIssuer(tt.issuer)
			if tt.wantFound {
				if validator == nil {
					t.Errorf("expected validator for issuer %q, got nil", tt.issuer)
					return
				}
				if validator.ProviderName() != tt.wantProvider {
					t.Errorf("got provider %q, want %q", validator.ProviderName(), tt.wantProvider)
				}
			} else {
				if validator != nil {
					t.Errorf("expected no validator for issuer %q, got %q", tt.issuer, validator.ProviderName())
				}
			}
		})
	}
}

// TestExternalIdPRegistryListProviders tests listing registered providers.
func TestExternalIdPRegistryListProviders(t *testing.T) {
	registry := &ExternalIdPRegistry{
		validators: make(map[string]ExternalIdPValidator),
	}

	// Empty registry
	providers := registry.ListProviders()
	if len(providers) != 0 {
		t.Errorf("expected empty list, got %v", providers)
	}

	// Register validators
	registry.Register(&mockValidator{name: "google", patterns: []string{"https://accounts.google.com"}})
	registry.Register(&mockValidator{name: "entra", patterns: []string{"https://login.microsoftonline.com/"}})

	providers = registry.ListProviders()
	if len(providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(providers))
	}

	// Check both are present (order not guaranteed)
	hasGoogle := false
	hasEntra := false
	for _, p := range providers {
		if p == "google" {
			hasGoogle = true
		}
		if p == "entra" {
			hasEntra = true
		}
	}
	if !hasGoogle || !hasEntra {
		t.Errorf("expected google and entra, got %v", providers)
	}
}

// mockValidator is a test implementation of ExternalIdPValidator.
type mockValidator struct {
	name     string
	patterns []string
}

func (m *mockValidator) Validate(ctx context.Context, token string) (*ExternalIdPClaims, error) {
	return &ExternalIdPClaims{
		Subject: "test-subject",
		Email:   "test@example.com",
	}, nil
}

func (m *mockValidator) ProviderName() string {
	return m.name
}

func (m *mockValidator) AuthProviderName() string {
	return m.name + "-auth-provider"
}

func (m *mockValidator) AuthProviderNamespace() string {
	return "default"
}

func (m *mockValidator) IssuerPatterns() []string {
	return m.patterns
}

// createTestJWT creates a minimal JWT for testing purposes.
// Note: This JWT has no valid signature - it's only for testing payload extraction.
func createTestJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payload)

	// Signature is not validated in our issuer extraction
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))

	return header + "." + payloadEncoded + "." + signature
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
