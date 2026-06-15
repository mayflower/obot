package oauth

import (
	"context"
	"fmt"
	"os"
	"strings"

	"google.golang.org/api/idtoken"
)

const (
	googleProviderName          = "google"
	googleAuthProviderName      = "google-auth-provider"
	googleAuthProviderNamespace = "default"
)

// GoogleIdPValidator validates Google ID tokens using Google's JWKS.
// It implements the ExternalIdPValidator interface.
type GoogleIdPValidator struct {
	clientID       string
	allowedDomains []string
	allowedHDs     []string // Google Workspace hosted domains
}

// NewGoogleIdPValidator creates a new Google IdP validator from environment configuration.
// Returns an error if OBOT_GOOGLE_CLIENT_ID is not configured.
func NewGoogleIdPValidator() (*GoogleIdPValidator, error) {
	clientID := os.Getenv("OBOT_GOOGLE_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("OBOT_GOOGLE_CLIENT_ID not configured")
	}

	validator := &GoogleIdPValidator{
		clientID: clientID,
	}

	// Parse allowed email domains
	if domains := os.Getenv("OBOT_GOOGLE_ALLOWED_DOMAINS"); domains != "" {
		validator.allowedDomains = splitAndTrim(domains)
	}

	// Parse allowed Google Workspace hosted domains
	if hds := os.Getenv("OBOT_GOOGLE_ALLOWED_HDS"); hds != "" {
		validator.allowedHDs = splitAndTrim(hds)
	}

	if len(validator.allowedDomains) == 0 && len(validator.allowedHDs) == 0 && !envBool("OBOT_GOOGLE_ALLOW_ALL_DOMAINS") {
		return nil, fmt.Errorf("OBOT_GOOGLE_ALLOWED_DOMAINS or OBOT_GOOGLE_ALLOWED_HDS must be configured, or set OBOT_GOOGLE_ALLOW_ALL_DOMAINS=true")
	}

	return validator, nil
}

// Validate verifies a Google ID token and returns the extracted claims.
// It uses Google's official idtoken library which handles:
// - JWKS fetching and caching
// - Signature verification
// - Expiration checks
// - Audience validation
func (v *GoogleIdPValidator) Validate(ctx context.Context, token string) (*ExternalIdPClaims, error) {
	// Use Google's idtoken library for validation
	payload, err := idtoken.Validate(ctx, token, v.clientID)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Extract and validate email_verified claim
	emailVerified, _ := payload.Claims["email_verified"].(bool)
	if !emailVerified {
		return nil, fmt.Errorf("email not verified")
	}

	// Extract email (required)
	email, ok := payload.Claims["email"].(string)
	if !ok || email == "" {
		return nil, fmt.Errorf("email claim missing or empty")
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
			if strings.ToLower(d) == domain {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("email domain not allowed")
		}
	}

	// Check Google Workspace hosted domain allowlist if configured
	if len(v.allowedHDs) > 0 {
		hd, _ := payload.Claims["hd"].(string)
		if hd == "" {
			return nil, fmt.Errorf("hosted domain claim required but not present")
		}
		allowed := false
		for _, d := range v.allowedHDs {
			if strings.EqualFold(d, hd) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("hosted domain not allowed")
		}
	}

	// Extract optional claims
	name, _ := payload.Claims["name"].(string)
	picture, _ := payload.Claims["picture"].(string)

	return &ExternalIdPClaims{
		Subject:       payload.Subject,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Picture:       picture,
	}, nil
}

// ProviderName returns "google" as the canonical provider name.
func (v *GoogleIdPValidator) ProviderName() string {
	return googleProviderName
}

// AuthProviderName returns the auth provider name used in Obot's identity system.
func (v *GoogleIdPValidator) AuthProviderName() string {
	return googleAuthProviderName
}

// AuthProviderNamespace returns the namespace for the auth provider.
func (v *GoogleIdPValidator) AuthProviderNamespace() string {
	return googleAuthProviderNamespace
}

// IssuerPatterns returns patterns that match Google ID token issuers.
// Google uses "https://accounts.google.com" as the issuer.
func (v *GoogleIdPValidator) IssuerPatterns() []string {
	return []string{
		"https://accounts.google.com",
		"accounts.google.com",
	}
}
