package oauth

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDCIdPValidator validates tokens from any standard OIDC-compliant provider
// (Dex, Keycloak, Auth0, Okta, etc.). It implements the ExternalIdPValidator interface.
type OIDCIdPValidator struct {
	issuer           string
	allowedAudiences []string
	providerName     string
	authProvider     string
	allowedDomains   []string

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// NewOIDCIdPValidator creates a new generic OIDC validator from environment configuration.
// Returns an error if OBOT_OIDC_ISSUER or OBOT_OIDC_CLIENT_ID are not configured.
//
// OBOT_OIDC_CLIENT_ID may be a comma-separated list of client IDs; the
// validator accepts a token whose `aud` claim matches any entry in the list.
// This lets a single Obot deployment serve multiple downstream OAuth clients
// (e.g. a portal client and a CLI client) that share the same OIDC issuer.
func NewOIDCIdPValidator() (*OIDCIdPValidator, error) {
	issuer := os.Getenv("OBOT_OIDC_ISSUER")
	if issuer == "" {
		return nil, fmt.Errorf("OBOT_OIDC_ISSUER not configured")
	}

	rawClientIDs := os.Getenv("OBOT_OIDC_CLIENT_ID")
	if rawClientIDs == "" {
		return nil, fmt.Errorf("OBOT_OIDC_CLIENT_ID not configured")
	}
	allowedAudiences := splitAndTrim(rawClientIDs)
	if len(allowedAudiences) == 0 {
		return nil, fmt.Errorf("OBOT_OIDC_CLIENT_ID has no non-empty entries")
	}

	providerName := os.Getenv("OBOT_OIDC_PROVIDER_NAME")
	if providerName == "" {
		providerName = "oidc"
	}

	authProvider := os.Getenv("OBOT_OIDC_AUTH_PROVIDER_NAME")
	if authProvider == "" {
		authProvider = providerName + "-auth-provider"
	}

	validator := &OIDCIdPValidator{
		issuer:           strings.TrimRight(issuer, "/"),
		allowedAudiences: allowedAudiences,
		providerName:     providerName,
		authProvider:     authProvider,
	}

	if domains := os.Getenv("OBOT_OIDC_ALLOWED_DOMAINS"); domains != "" {
		validator.allowedDomains = splitAndTrim(domains)
	}
	if len(validator.allowedDomains) == 0 && !envBool("OBOT_OIDC_ALLOW_ALL_DOMAINS") {
		return nil, fmt.Errorf("OBOT_OIDC_ALLOWED_DOMAINS must be configured, or set OBOT_OIDC_ALLOW_ALL_DOMAINS=true")
	}

	return validator, nil
}

// splitAndTrim splits a comma-separated string and drops empty entries.
func splitAndTrim(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// audienceMatches reports whether any value in the token audience appears
// in the allowed list. Empty allowed lists never match.
func audienceMatches(tokenAudience, allowed []string) bool {
	if len(allowed) == 0 || len(tokenAudience) == 0 {
		return false
	}
	for _, want := range allowed {
		for _, got := range tokenAudience {
			if got == want {
				return true
			}
		}
	}
	return false
}

// getVerifier lazily initializes the OIDC verifier on first use.
// This avoids startup failures if the OIDC provider isn't reachable yet.
//
// The verifier is created with SkipClientIDCheck=true because go-oidc's
// Config.ClientID only accepts a single string. Audience validation is done
// manually in Validate() against allowedAudiences so multiple downstream
// OAuth clients can share the same Obot deployment.
func (v *OIDCIdPValidator) getVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.verifier != nil {
		return v.verifier, nil
	}

	provider, err := oidc.NewProvider(ctx, v.issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed for %s: %w", v.issuer, err)
	}

	v.verifier = provider.Verifier(&oidc.Config{
		SkipClientIDCheck: true,
	})

	return v.verifier, nil
}

// Validate verifies an OIDC ID token and returns the extracted claims.
func (v *OIDCIdPValidator) Validate(ctx context.Context, tokenString string) (*ExternalIdPClaims, error) {
	verifier, err := v.getVerifier(ctx)
	if err != nil {
		return nil, err
	}

	idToken, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Manual audience check (go-oidc verifier was created with
	// SkipClientIDCheck=true to support multiple allowed audiences).
	if !audienceMatches(idToken.Audience, v.allowedAudiences) {
		return nil, fmt.Errorf("token audience %v does not match any allowed audience %v", idToken.Audience, v.allowedAudiences)
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("email claim missing")
	}

	if !claims.EmailVerified {
		return nil, fmt.Errorf("email not verified")
	}

	if len(v.allowedDomains) > 0 {
		parts := strings.Split(claims.Email, "@")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid email format")
		}
		domain := strings.ToLower(parts[1])
		allowed := false
		for _, d := range v.allowedDomains {
			if strings.EqualFold(d, domain) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("email domain not allowed")
		}
	}

	return &ExternalIdPClaims{
		Subject:       idToken.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		Picture:       claims.Picture,
	}, nil
}

func (v *OIDCIdPValidator) ProviderName() string          { return v.providerName }
func (v *OIDCIdPValidator) AuthProviderName() string      { return v.authProvider }
func (v *OIDCIdPValidator) AuthProviderNamespace() string { return "default" }

// IssuerPatterns returns the configured issuer URL as the exact match pattern.
func (v *OIDCIdPValidator) IssuerPatterns() []string {
	return []string{v.issuer}
}
