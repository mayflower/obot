package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// ExternalIdPClaims represents validated claims from an external Identity Provider.
// All providers must map their claims to this common structure.
type ExternalIdPClaims struct {
	// Subject is the unique identifier for the user at the IdP (e.g., Google's 'sub' claim)
	Subject string
	// Email is the user's email address
	Email string
	// EmailVerified indicates whether the email has been verified by the IdP
	EmailVerified bool
	// Name is the user's display name (optional)
	Name string
	// Picture is a URL to the user's profile picture (optional)
	Picture string
}

// ExternalIdPValidator defines the interface for validating tokens from external Identity Providers.
// Implementations handle provider-specific validation logic (e.g., JWKS fetching, signature verification).
type ExternalIdPValidator interface {
	// Validate verifies the token and returns the extracted claims.
	// Returns an error if the token is invalid, expired, or doesn't meet requirements.
	Validate(ctx context.Context, token string) (*ExternalIdPClaims, error)

	// ProviderName returns the canonical name for this IdP (e.g., "google", "microsoft", "github").
	// This is used for logging and to construct the auth provider name in Obot.
	ProviderName() string

	// AuthProviderName returns the full auth provider name used in Obot's identity system.
	// (e.g., "google-auth-provider", "microsoft-auth-provider")
	AuthProviderName() string

	// AuthProviderNamespace returns the namespace for the auth provider (typically "default").
	AuthProviderNamespace() string

	// IssuerPatterns returns patterns that match the "iss" claim for tokens from this IdP.
	// Patterns can be exact matches or prefixes (e.g., "https://accounts.google.com" or "https://login.microsoftonline.com/").
	// This is used for routing incoming tokens to the correct validator.
	IssuerPatterns() []string
}

// ExternalIdPRegistry manages registered external IdP validators.
// It provides thread-safe access to validators and supports runtime registration.
type ExternalIdPRegistry struct {
	mu         sync.RWMutex
	validators map[string]ExternalIdPValidator
}

// NewExternalIdPRegistry creates a new registry with default validators.
// Validators are registered based on their environment configuration.
func NewExternalIdPRegistry(config ExternalIdPConfig) *ExternalIdPRegistry {
	registry := &ExternalIdPRegistry{
		validators: make(map[string]ExternalIdPValidator),
	}

	// Register Google validator if configured
	if googleValidator, err := NewGoogleIdPValidator(); err == nil {
		registry.Register(googleValidator)
		log.Infof("Registered external IdP validator: %s", googleValidator.ProviderName())
	}

	// Register Entra ID validator if configured
	if entraValidator, err := NewEntraIdPValidator(); err == nil {
		registry.Register(entraValidator)
		log.Infof("Registered external IdP validator: %s", entraValidator.ProviderName())
	}

	// Log configuration
	if len(config.AllowedClientIDs) > 0 {
		log.Infof("External IdP token exchange enabled for clients: %v", config.AllowedClientIDs)
	} else {
		log.Warnf("External IdP token exchange disabled: OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS not configured")
	}

	return registry
}

// Register adds a validator to the registry.
// If a validator with the same provider name already exists, it will be replaced.
func (r *ExternalIdPRegistry) Register(v ExternalIdPValidator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.validators[v.ProviderName()] = v
}

// Get retrieves a validator by provider name.
// Returns nil if no validator is registered for the given provider.
func (r *ExternalIdPRegistry) Get(providerName string) ExternalIdPValidator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.validators[providerName]
}

// ValidateToken validates a token using the appropriate validator based on the token's issuer.
// It first extracts the issuer from the token (without verification) to route to the correct validator,
// then performs full validation using that validator.
//
// Returns the claims and the validator that succeeded, or an error if validation fails.
//
// Note: This copies validators under lock and then validates without holding the lock,
// to avoid holding the lock during potentially slow network operations (JWKS fetching, etc.).
func (r *ExternalIdPRegistry) ValidateToken(ctx context.Context, token string) (*ExternalIdPClaims, ExternalIdPValidator, error) {
	// Extract issuer from token (without verification) for routing
	issuer, err := extractIssuerFromJWT(token)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid token format: %w", err)
	}

	// Find validator by issuer pattern
	validator := r.findValidatorByIssuer(issuer)
	if validator == nil {
		return nil, nil, fmt.Errorf("unsupported issuer: %s", issuer)
	}

	// Validate using the matched validator
	claims, err := validator.Validate(ctx, token)
	if err != nil {
		return nil, nil, err
	}

	return claims, validator, nil
}

// findValidatorByIssuer finds a validator that matches the given issuer.
// Returns nil if no matching validator is found.
func (r *ExternalIdPRegistry) findValidatorByIssuer(issuer string) ExternalIdPValidator {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, validator := range r.validators {
		for _, pattern := range validator.IssuerPatterns() {
			// Support both exact match and prefix match
			if issuer == pattern || strings.HasPrefix(issuer, pattern) {
				return validator
			}
		}
	}
	return nil
}

// extractIssuerFromJWT extracts the "iss" claim from a JWT without verifying the signature.
// This is used only for routing purposes - full verification is done by the validator.
func extractIssuerFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64 with padding
		payload, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("failed to decode JWT payload: %w", err)
		}
	}

	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	if claims.Issuer == "" {
		return "", fmt.Errorf("missing issuer claim")
	}

	return claims.Issuer, nil
}

// ListProviders returns a list of all registered provider names.
func (r *ExternalIdPRegistry) ListProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	providers := make([]string, 0, len(r.validators))
	for name := range r.validators {
		providers = append(providers, name)
	}
	return providers
}
