package oauth

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
)

// Regex to extract tenant ID from v1 issuers (sts.windows.net/{tenant}/)
var stsIssuerRegex = regexp.MustCompile(`^https://sts\.windows\.net/([^/]+)/?$`)

const (
	entraProviderName          = "entra"
	entraAuthProviderName      = "entra-auth-provider"
	entraAuthProviderNamespace = "default"
)

// EntraIdPValidator validates Microsoft Entra ID tokens using go-oidc.
// It implements the ExternalIdPValidator interface.
type EntraIdPValidator struct {
	clientID       string
	tenantID       string   // "common" for multi-tenant, or specific tenant ID
	allowedTenants []string // Restrict to specific tenant IDs
	allowedDomains []string // Restrict to specific email domains

	// Per-issuer OIDC verifiers (cached)
	verifiers sync.Map // map[string]*oidc.IDTokenVerifier
}

// NewEntraIdPValidator creates a new Entra ID validator from environment configuration.
// Returns an error if OBOT_ENTRA_CLIENT_ID is not configured.
func NewEntraIdPValidator() (*EntraIdPValidator, error) {
	clientID := os.Getenv("OBOT_ENTRA_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("OBOT_ENTRA_CLIENT_ID not configured")
	}

	tenantID := os.Getenv("OBOT_ENTRA_TENANT_ID")
	allowAnyTenant := envBool("OBOT_ENTRA_ALLOW_ANY_TENANT")

	validator := &EntraIdPValidator{
		clientID: clientID,
		tenantID: strings.TrimSpace(tenantID),
	}

	// Parse allowed tenant IDs
	if tenants := os.Getenv("OBOT_ENTRA_ALLOWED_TENANTS"); tenants != "" {
		validator.allowedTenants = splitAndTrim(tenants)
	}

	// Parse allowed email domains
	if domains := os.Getenv("OBOT_ENTRA_ALLOWED_DOMAINS"); domains != "" {
		validator.allowedDomains = splitAndTrim(domains)
	}

	if validator.tenantID == "" && !allowAnyTenant {
		return nil, fmt.Errorf("OBOT_ENTRA_TENANT_ID must be configured, or set OBOT_ENTRA_ALLOW_ANY_TENANT=true")
	}
	if validator.tenantID == "common" && len(validator.allowedTenants) == 0 && len(validator.allowedDomains) == 0 && !allowAnyTenant {
		return nil, fmt.Errorf("OBOT_ENTRA_ALLOWED_TENANTS or OBOT_ENTRA_ALLOWED_DOMAINS must be configured for common tenant, or set OBOT_ENTRA_ALLOW_ANY_TENANT=true")
	}
	if validator.tenantID == "" {
		validator.tenantID = "common"
	}

	return validator, nil
}

// Validate verifies a Microsoft Entra ID token and returns the extracted claims.
func (v *EntraIdPValidator) Validate(ctx context.Context, tokenString string) (*ExternalIdPClaims, error) {
	// Parse token without verification first to get issuer
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverifiedToken, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims format")
	}

	issuer, _ := unverifiedClaims["iss"].(string)
	if issuer == "" {
		return nil, fmt.Errorf("missing issuer claim")
	}

	// Get or create OIDC verifier for this issuer
	verifier, err := v.getVerifier(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to get OIDC verifier: %w", err)
	}

	// Verify the token
	idToken, err := verifier.Verify(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Extract claims into a map
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	tid, _ := claims["tid"].(string)
	if v.tenantID != "" && v.tenantID != "common" && tid != v.tenantID {
		return nil, fmt.Errorf("tenant does not match configured tenant")
	}

	// Validate tenant if restrictions are configured
	if len(v.allowedTenants) > 0 {
		if tid == "" {
			return nil, fmt.Errorf("missing tenant ID claim")
		}
		allowed := false
		for _, t := range v.allowedTenants {
			if t == tid {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("tenant not allowed")
		}
	}

	// Extract email - try multiple claims as Microsoft tokens can have different structures
	email := v.extractEmail(claims)
	if email == "" {
		return nil, fmt.Errorf("email claim missing")
	}

	// Check email domain allowlist if configured
	if len(v.allowedDomains) > 0 {
		parts := strings.Split(email, "@")
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

	// Use 'oid' (Object ID) as the stable identifier, not 'sub'
	// 'sub' is pairwise and can change per application, 'oid' is stable within tenant
	oid, _ := claims["oid"].(string)
	if oid == "" {
		// Fall back to 'sub' if 'oid' is not present
		oid = idToken.Subject
	}
	if oid == "" {
		return nil, fmt.Errorf("missing oid/sub claim")
	}

	name, _ := claims["name"].(string)

	return &ExternalIdPClaims{
		Subject:       oid,
		Email:         email,
		EmailVerified: true, // Microsoft tokens are issued for verified emails
		Name:          name,
		Picture:       "", // Microsoft tokens don't typically include picture
	}, nil
}

// getVerifier returns an OIDC verifier for the given issuer, creating one if needed.
func (v *EntraIdPValidator) getVerifier(ctx context.Context, issuer string) (*oidc.IDTokenVerifier, error) {
	// Check cache first
	if cached, ok := v.verifiers.Load(issuer); ok {
		return cached.(*oidc.IDTokenVerifier), nil
	}

	// Determine the OIDC provider URL
	// Handle v1 issuers (sts.windows.net) by mapping to v2 endpoint
	providerURL := v.getProviderURL(issuer)

	// Create OIDC provider (handles discovery and JWKS caching)
	provider, err := oidc.NewProvider(ctx, providerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for %s: %w", providerURL, err)
	}

	// Create verifier with our client ID as the expected audience
	// Skip issuer check since we handle v1/v2 issuer mapping
	verifier := provider.Verifier(&oidc.Config{
		ClientID:          v.clientID,
		SkipIssuerCheck:   true, // We verify issuer pattern in IssuerPatterns()
		SkipClientIDCheck: false,
	})

	// Cache the verifier
	v.verifiers.Store(issuer, verifier)

	return verifier, nil
}

// getProviderURL returns the OIDC provider URL for the given issuer.
// Handles both v1 (sts.windows.net) and v2 (login.microsoftonline.com) issuers.
func (v *EntraIdPValidator) getProviderURL(issuer string) string {
	// Check if this is a v1 issuer (sts.windows.net)
	if matches := stsIssuerRegex.FindStringSubmatch(issuer); len(matches) == 2 {
		tenantID := matches[1]
		// Use v2 provider URL for v1 issuers
		return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
	}

	// For v2 issuers, use as-is
	return issuer
}

// extractEmail extracts the email from Microsoft token claims.
// Microsoft tokens can have email in different claims depending on token type.
func (v *EntraIdPValidator) extractEmail(claims map[string]interface{}) string {
	// Try standard email claim first
	if email, ok := claims["email"].(string); ok && email != "" {
		return email
	}
	// Try preferred_username (often the email)
	if upn, ok := claims["preferred_username"].(string); ok && upn != "" {
		return upn
	}
	// Try upn (User Principal Name)
	if upn, ok := claims["upn"].(string); ok && upn != "" {
		return upn
	}
	return ""
}

// ProviderName returns "entra" as the canonical provider name.
func (v *EntraIdPValidator) ProviderName() string {
	return entraProviderName
}

// AuthProviderName returns the auth provider name used in Obot's identity system.
func (v *EntraIdPValidator) AuthProviderName() string {
	return entraAuthProviderName
}

// AuthProviderNamespace returns the namespace for the auth provider.
func (v *EntraIdPValidator) AuthProviderNamespace() string {
	return entraAuthProviderNamespace
}

// IssuerPatterns returns patterns that match Microsoft Entra ID token issuers.
// Microsoft uses multiple issuer formats depending on v1.0 vs v2.0 tokens and tenant configuration.
func (v *EntraIdPValidator) IssuerPatterns() []string {
	return []string{
		"https://login.microsoftonline.com/",
		"https://sts.windows.net/",
	}
}
