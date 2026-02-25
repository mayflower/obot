package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/obot-platform/obot/pkg/auth"
	"github.com/obot-platform/obot/pkg/gateway/client"
	"github.com/obot-platform/obot/pkg/gateway/server/dispatcher"
	"github.com/obot-platform/obot/pkg/jwt/persistent"
	"gorm.io/gorm"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type gatewayTokenReview struct {
	gatewayClient *client.Client
	dispatcher    *dispatcher.Dispatcher
	tokenService  *persistent.TokenService
}

func NewGatewayTokenReviewer(gatewayClient *client.Client, dispatcher *dispatcher.Dispatcher, tokenService *persistent.TokenService) authenticator.Request {
	return &gatewayTokenReview{
		gatewayClient: gatewayClient,
		dispatcher:    dispatcher,
		tokenService:  tokenService,
	}
}

func (g *gatewayTokenReview) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	bearer := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	if bearer == "" {
		bearer = req.Header.Get("X-API-Key")
		if bearer == "" {
			return nil, false, nil
		}
	}

	// Try JWT validation first (for RFC 8693 exchanged tokens)
	// This provides stateless authentication via JWKS without database lookups.
	if g.tokenService != nil {
		if tokenCtx, err := g.tokenService.DecodeToken(req.Context(), bearer); err == nil {
			// JWT validation succeeded - extract user info from claims
			namespace := tokenCtx.AuthProviderNamespace
			name := tokenCtx.AuthProviderName

			// populateContext sets up the auth provider URL in the request context.
			// For external IdP tokens, the auth provider may not exist as a running
			// provider, so we ignore errors here.
			_ = populateContext(req, g.dispatcher, namespace, name)

			return &authenticator.Response{
				User: &user.DefaultInfo{
					Name:   tokenCtx.UserName,
					UID:    tokenCtx.UserID,
					Groups: tokenCtx.UserGroups,
					Extra: map[string][]string{
						"email":                   {tokenCtx.UserEmail},
						"auth_provider_namespace": {namespace},
						"auth_provider_name":      {name},
					},
				},
			}, true, nil
		}
		// JWT validation failed - fall through to database token lookup
	}

	// Fall back to database token lookup (backwards compatibility with existing tokens)
	u, namespace, name, providerUserID, groupIDs, err := g.gatewayClient.UserFromToken(req.Context(), bearer)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}

	// populateContext sets up the auth provider URL in the request context.
	// For external IdP tokens (e.g., from RFC 8693 token exchange), the auth provider
	// may not exist as a running provider, so we ignore errors here.
	// The provider URL is only needed for fetching group info from the provider.
	_ = populateContext(req, g.dispatcher, namespace, name)

	return &authenticator.Response{
		User: &user.DefaultInfo{
			Name: u.Username,
			UID:  providerUserID,
			Extra: map[string][]string{
				"email":                   {u.Email},
				"auth_provider_namespace": {namespace},
				"auth_provider_name":      {name},
				"auth_provider_groups":    groupIDs,
			},
		},
	}, true, nil
}

func populateContext(req *http.Request, dispatcher *dispatcher.Dispatcher, namespace, name string) error {
	providerURL, err := dispatcher.URLForAuthProvider(req.Context(), namespace, name)
	if err != nil {
		return err
	}

	// Store the provider URL in context for later group fetching
	*req = *req.WithContext(auth.ContextWithProviderURL(req.Context(), providerURL.String()))

	return nil
}
