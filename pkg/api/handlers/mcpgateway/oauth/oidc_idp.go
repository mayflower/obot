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
	issuer         string
	clientID       string
	providerName   string
	authProvider   string
	allowedDomains []string

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

// NewOIDCIdPValidator creates a new generic OIDC validator from environment configuration.
// Returns an error if OBOT_OIDC_ISSUER or OBOT_OIDC_CLIENT_ID are not configured.
func NewOIDCIdPValidator() (*OIDCIdPValidator, error) {
	issuer := os.Getenv("OBOT_OIDC_ISSUER")
	if issuer == "" {
		return nil, fmt.Errorf("OBOT_OIDC_ISSUER not configured")
	}

	clientID := os.Getenv("OBOT_OIDC_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("OBOT_OIDC_CLIENT_ID not configured")
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
		issuer:       strings.TrimRight(issuer, "/"),
		clientID:     clientID,
		providerName: providerName,
		authProvider: authProvider,
	}

	if domains := os.Getenv("OBOT_OIDC_ALLOWED_DOMAINS"); domains != "" {
		validator.allowedDomains = strings.Split(domains, ",")
		for i := range validator.allowedDomains {
			validator.allowedDomains[i] = strings.TrimSpace(validator.allowedDomains[i])
		}
	}

	return validator, nil
}

// getVerifier lazily initializes the OIDC verifier on first use.
// This avoids startup failures if the OIDC provider isn't reachable yet.
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
		ClientID: v.clientID,
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

func (v *OIDCIdPValidator) ProviderName() string         { return v.providerName }
func (v *OIDCIdPValidator) AuthProviderName() string      { return v.authProvider }
func (v *OIDCIdPValidator) AuthProviderNamespace() string { return "default" }

// IssuerPatterns returns the configured issuer URL as the exact match pattern.
func (v *OIDCIdPValidator) IssuerPatterns() []string {
	return []string{v.issuer}
}
