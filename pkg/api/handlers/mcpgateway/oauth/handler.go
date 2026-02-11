package oauth

import (
	"os"
	"strings"
	"time"

	"github.com/obot-platform/obot/pkg/api/handlers"
	"github.com/obot-platform/obot/pkg/api/server"
	"github.com/obot-platform/obot/pkg/jwt/persistent"
	"github.com/obot-platform/obot/pkg/mcp"
)

// ExternalIdPConfig holds configuration for external IdP token exchange.
type ExternalIdPConfig struct {
	// AllowedClientIDs restricts which OAuth clients can use external IdP token exchange.
	// If empty, external IdP token exchange is disabled.
	AllowedClientIDs []string

	// AutoProvision allows creating new users via external IdP token exchange.
	// If false, only pre-existing users can authenticate via external IdP.
	AutoProvision bool
}

// NewExternalIdPConfig creates configuration from environment variables.
func NewExternalIdPConfig() ExternalIdPConfig {
	config := ExternalIdPConfig{
		AutoProvision: true, // Default to enabled for development convenience
	}

	// Parse allowed client IDs
	if clients := os.Getenv("OBOT_EXTERNAL_IDP_ALLOWED_CLIENTS"); clients != "" {
		config.AllowedClientIDs = strings.Split(clients, ",")
		for i := range config.AllowedClientIDs {
			config.AllowedClientIDs[i] = strings.TrimSpace(config.AllowedClientIDs[i])
		}
	}

	// Parse auto-provision setting
	if autoProvision := os.Getenv("OBOT_EXTERNAL_IDP_AUTO_PROVISION"); autoProvision != "" {
		config.AutoProvision = autoProvision == "true" || autoProvision == "1"
	}

	return config
}

// IsClientAllowed checks if a client ID is allowed to use external IdP token exchange.
func (c ExternalIdPConfig) IsClientAllowed(clientID string) bool {
	if len(c.AllowedClientIDs) == 0 {
		return false // No clients allowed if not configured
	}
	for _, allowed := range c.AllowedClientIDs {
		if allowed == clientID {
			return true
		}
	}
	return false
}

type handler struct {
	oauthChecker     *MCPOAuthHandlerFactory
	tokenService     *persistent.TokenService
	oauthConfig      handlers.OAuthAuthorizationServerConfig
	tokenStore       mcp.GlobalTokenStore
	baseURL          string
	authCompleteURL  string
	clientExpiration time.Duration
	idpRegistry      *ExternalIdPRegistry
	externalIdPConf  ExternalIdPConfig
}

func SetupHandlers(oauthChecker *MCPOAuthHandlerFactory, tokenStore mcp.GlobalTokenStore, tokenService *persistent.TokenService, oauthConfig handlers.OAuthAuthorizationServerConfig, baseURL string, authCompleteURL string, clientSecretExpiration time.Duration, mux *server.Server) {
	externalIdPConf := NewExternalIdPConfig()
	h := &handler{
		tokenStore:       tokenStore,
		tokenService:     tokenService,
		oauthConfig:      oauthConfig,
		baseURL:          baseURL,
		authCompleteURL:  authCompleteURL,
		oauthChecker:     oauthChecker,
		clientExpiration: clientSecretExpiration,
		idpRegistry:      NewExternalIdPRegistry(externalIdPConf),
		externalIdPConf:  externalIdPConf,
	}

	// Expose two sets of endpoints: one for clients that look at the oauth-protected-resource metadata and one for clients that don't.
	// Clients that don't look at the metadata must use a resource parameter when authorizing.
	mux.HandleFunc("POST /oauth/register/{mcp_id}", h.register)
	mux.HandleFunc("POST /oauth/register", h.register)
	mux.HandleFunc("GET /oauth/authorize/{mcp_id}", h.authorize)
	mux.HandleFunc("GET /oauth/authorize", h.authorize)
	mux.HandleFunc("POST /oauth/token/{mcp_id}", h.token)
	mux.HandleFunc("POST /oauth/token", h.token)

	// This is the callback that Obot will redirect to after the user has authenticated.
	// It checks for second-level OAuth and redirects there, if necessary.
	// Otherwise, it redirects to the original redirect URI with the authorization code.
	mux.HandleFunc("GET /oauth/callback/{oauth_auth_request}", h.callback)

	mux.HandleFunc("GET /oauth/register/{client}", h.readClient)
	mux.HandleFunc("PUT /oauth/register/{client}", h.updateClient)
	mux.HandleFunc("DELETE /oauth/register/{client}", h.deleteClient)

	// This is the callback handler for second-level OAuth.
	// In other words, the third-party OAuth will redirect here.
	mux.HandleFunc("GET /oauth/mcp/callback", h.oauthCallback)

	mux.HandleFunc("GET /oauth/jwks.json", h.tokenService.ServeJWKS)
	mux.HandleFunc("POST /oauth/replace-jwks", h.tokenService.ReplaceJWK)

	mux.HandleFunc("GET /api/oauth/composite/{mcp_id}", h.checkCompositeAuth)

	mux.HandleFunc("GET /oauth/userinfo", h.userInfo)
}
