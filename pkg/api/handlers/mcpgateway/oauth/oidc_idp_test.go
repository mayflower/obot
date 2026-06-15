package oauth

import (
	"testing"
)

func TestSplitAndTrim(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", []string{}},
		{"single", "client-a", []string{"client-a"}},
		{"two", "client-a,client-b", []string{"client-a", "client-b"}},
		{"with spaces", "  client-a , client-b  ", []string{"client-a", "client-b"}},
		{"empty entries dropped", "client-a,,client-b,", []string{"client-a", "client-b"}},
		{"only commas", ",,,", []string{}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitAndTrim(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("at index %d: expected %q, got %q", i, tc.want[i], got[i])
				}
			}
		})
	}
}

func TestAudienceMatches(t *testing.T) {
	cases := []struct {
		name          string
		tokenAudience []string
		allowed       []string
		want          bool
	}{
		{
			name:          "exact single match",
			tokenAudience: []string{"langopen-cli"},
			allowed:       []string{"langopen-cli"},
			want:          true,
		},
		{
			name:          "second allowed value matches",
			tokenAudience: []string{"langopen-cli"},
			allowed:       []string{"maistack-research", "langopen-cli"},
			want:          true,
		},
		{
			name:          "no match",
			tokenAudience: []string{"unknown-client"},
			allowed:       []string{"maistack-research", "langopen-cli"},
			want:          false,
		},
		{
			name:          "multi-audience token, one matches",
			tokenAudience: []string{"unknown-client", "langopen-cli"},
			allowed:       []string{"langopen-cli"},
			want:          true,
		},
		{
			name:          "empty allowed list rejects",
			tokenAudience: []string{"langopen-cli"},
			allowed:       []string{},
			want:          false,
		},
		{
			name:          "empty token audience rejects",
			tokenAudience: []string{},
			allowed:       []string{"langopen-cli"},
			want:          false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := audienceMatches(tc.tokenAudience, tc.allowed); got != tc.want {
				t.Errorf("audienceMatches(%v, %v) = %v, want %v",
					tc.tokenAudience, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestNewOIDCIdPValidator_MultiAudience(t *testing.T) {
	t.Setenv("OBOT_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("OBOT_OIDC_CLIENT_ID", "maistack-research,langopen-cli")
	t.Setenv("OBOT_OIDC_PROVIDER_NAME", "dex")
	t.Setenv("OBOT_OIDC_ALLOWED_DOMAINS", "example.com")

	v, err := NewOIDCIdPValidator()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := len(v.allowedAudiences); got != 2 {
		t.Fatalf("expected 2 allowed audiences, got %d: %v", got, v.allowedAudiences)
	}
	if v.allowedAudiences[0] != "maistack-research" || v.allowedAudiences[1] != "langopen-cli" {
		t.Errorf("unexpected audiences: %v", v.allowedAudiences)
	}
}

func TestNewOIDCIdPValidator_RejectsEmptyClientID(t *testing.T) {
	t.Setenv("OBOT_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("OBOT_OIDC_CLIENT_ID", "")

	if _, err := NewOIDCIdPValidator(); err == nil {
		t.Fatal("expected error when OBOT_OIDC_CLIENT_ID is empty")
	}
}

func TestNewOIDCIdPValidator_RejectsCommasOnly(t *testing.T) {
	t.Setenv("OBOT_OIDC_ISSUER", "https://id.example.com")
	t.Setenv("OBOT_OIDC_CLIENT_ID", ",, ,")

	if _, err := NewOIDCIdPValidator(); err == nil {
		t.Fatal("expected error when OBOT_OIDC_CLIENT_ID has no usable entries")
	}
}
