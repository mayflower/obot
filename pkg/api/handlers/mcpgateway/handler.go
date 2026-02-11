package mcpgateway

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gptscript-ai/go-gptscript"
	gtypes "github.com/gptscript-ai/gptscript/pkg/types"
	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	"github.com/obot-platform/obot/pkg/api/handlers"
	"github.com/obot-platform/obot/pkg/controller/handlers/systemmcpserver"
	"github.com/obot-platform/obot/pkg/mcp"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/obot-platform/obot/pkg/system"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type Handler struct {
	mcpSessionManager         *mcp.SessionManager
	webhookHelper             *mcp.WebhookHelper
	tokenService              mcp.TokenService
	nanobotIntegrationEnabled bool
	scope                     string
	transport                 http.RoundTripper
}

func NewHandler(mcpSessionManager *mcp.SessionManager, webhookHelper *mcp.WebhookHelper, tokenService mcp.TokenService, scopesSupported []string, nanobotIntegrationEnabled bool) *Handler {
	var scope string
	if len(scopesSupported) > 0 {
		scope = fmt.Sprintf(", scope=\"%s\"", strings.Join(scopesSupported, " "))
	}
	return &Handler{
		mcpSessionManager:         mcpSessionManager,
		webhookHelper:             webhookHelper,
		tokenService:              tokenService,
		nanobotIntegrationEnabled: nanobotIntegrationEnabled,
		scope:                     scope,
		transport:                 otelhttp.NewTransport(http.DefaultTransport),
	}
}

func (h *Handler) Proxy(req api.Context) error {
	if req.User.GetUID() == "anonymous" {
		req.ResponseWriter.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_request", error_description="Invalid access token", resource_metadata="%s/.well-known/oauth-protected-resource%s"%s`, strings.TrimSuffix(req.APIBaseURL, "/api"), req.URL.Path, h.scope))
		return apierrors.NewUnauthorized("user is not authenticated")
	}

	mcpURL, serverConfig, allowDifferentPaths, err := h.ensureServerIsDeployed(req)
	if err != nil {
		return fmt.Errorf("failed to ensure server is deployed: %v", err)
	}

	u, err := url.Parse(mcpURL)
	if err != nil {
		http.Error(req.ResponseWriter, err.Error(), http.StatusInternalServerError)
		return nil
	}

	// Create a JWT for the authenticated user to pass to the MCP server shim.
	now := time.Now().Add(-time.Second)
	audience := gtypes.FirstSet(serverConfig.Audiences...)

	issuer := serverConfig.Issuer
	if issuer == "" {
		if audURL, err := url.Parse(audience); err == nil {
			issuer = fmt.Sprintf("%s://%s", audURL.Scheme, audURL.Host)
		}
	}

	claims := jwt.MapClaims{
		"aud":   audience,
		"iss":   issuer,
		"exp":   float64(now.Add(time.Hour + 15*time.Minute).Unix()),
		"iat":   float64(now.Unix()),
		"sub":   req.User.GetUID(),
		"MCPID": serverConfig.MCPServerName,
	}

	_, token, err := h.tokenService.NewTokenWithClaims(req.Context(), claims)
	if err != nil {
		return fmt.Errorf("failed to create JWT for MCP proxy: %w", err)
	}

	(&httputil.ReverseProxy{
		Transport: h.transport,
		Director: func(r *http.Request) {
			r.Header.Set("X-Forwarded-Host", r.Host)
			scheme := "https"
			if strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.0.0.1") {
				scheme = "http"
			}
			r.Header.Set("X-Forwarded-Proto", scheme)

			// Replace the Authorization header with the new JWT
			r.Header.Set("Authorization", "Bearer "+token)

			r.Host = u.Host
			r.URL.Scheme = u.Scheme
			r.URL.Host = u.Host
			r.URL.Path = u.Path
			if rest := r.PathValue("rest"); allowDifferentPaths && rest != "" {
				if strings.HasPrefix(rest, "/") {
					r.URL.Path = rest
				} else {
					r.URL.Path = "/" + rest
				}
			}

			// Merge query parameters from the incoming request and the upstream URL.
			// Preserve all values; if a key exists in both, both values will be present.
			upstreamQuery := u.Query()
			origQuery := r.URL.Query()
			for k, vs := range origQuery {
				for _, v := range vs {
					upstreamQuery.Add(k, v)
				}
			}
			r.URL.RawQuery = upstreamQuery.Encode()
		},
	}).ServeHTTP(req.ResponseWriter, req.Request)

	return nil
}

func (h *Handler) ensureServerIsDeployed(req api.Context) (string, mcp.ServerConfig, bool, error) {
	mcpID := req.PathValue("mcp_id")

	if system.IsSystemMCPServerID(mcpID) {
		return h.ensureSystemServerIsDeployed(req, mcpID)
	}

	mcpID, mcpServer, mcpServerConfig, err := handlers.ServerForActionWithConnectID(req, mcpID)
	if err != nil {
		return "", mcp.ServerConfig{}, false, fmt.Errorf("failed to get mcp server config: %w", err)
	}
	if mcpServer.Spec.Template {
		return "", mcp.ServerConfig{}, false, apierrors.NewNotFound(schema.GroupResource{Group: "obot.obot.ai", Resource: "mcpserver"}, mcpID)
	}

	// Ad-hoc authorization for nanobot agents
	if h.nanobotIntegrationEnabled && mcpServerConfig.NanobotAgentName != "" {
		var agent v1.NanobotAgent
		if err = req.Get(&agent, mcpServerConfig.NanobotAgentName); err != nil {
			return "", mcp.ServerConfig{}, false, fmt.Errorf("failed to get nanobot agent %q: %w", mcpServerConfig.NanobotAgentName, err)
		}
		if agent.Spec.UserID != req.User.GetUID() && (!req.UserCanImpersonate() || !req.UserIsAdmin()) {
			return "", mcp.ServerConfig{}, false, types.NewErrForbidden("user is not authorized to access nanobot agent %q", mcpServerConfig.NanobotAgentName)
		}
	}

	url, transformedConfig, err := h.mcpSessionManager.LaunchServer(req.Context(), mcpServerConfig)
	if err != nil {
		return "", mcp.ServerConfig{}, false, fmt.Errorf("failed to launch mcp server: %w", err)
	}

	// Return transformedConfig instead of original mcpServerConfig
	// The transformed config has internal URLs (e.g., maistack-obot.default.svc.cluster.local)
	// which are needed for JWT issuer/audience to match what the MCP shim expects
	return url, transformedConfig, h.nanobotIntegrationEnabled && mcpServerConfig.NanobotAgentName != "", nil
}

func (h *Handler) ensureSystemServerIsDeployed(req api.Context, mcpID string) (string, mcp.ServerConfig, bool, error) {
	var systemServer v1.SystemMCPServer
	if err := req.Get(&systemServer, mcpID); err != nil {
		return "", mcp.ServerConfig{}, false, fmt.Errorf("failed to get system MCP server %q: %w", mcpID, err)
	}

	if systemServer.Spec.Manifest.Enabled != nil && !*systemServer.Spec.Manifest.Enabled {
		return "", mcp.ServerConfig{}, false, apierrors.NewNotFound(schema.GroupResource{Group: "obot.obot.ai", Resource: "systemmcpserver"}, mcpID)
	}

	// Only look up credentials if the manifest has env vars without static values.
	// This avoids expensive credential lookups on the hot path for servers like
	// obot-mcp-server where all env vars have static values.
	credEnv := make(map[string]string)
	needsCredentials := false
	for _, env := range systemServer.Spec.Manifest.Env {
		if env.Value == "" {
			needsCredentials = true
			break
		}
	}

	if needsCredentials {
		credCtx := systemServer.Name
		creds, err := req.GPTClient.ListCredentials(req.Context(), gptscript.ListCredentialsOptions{
			CredentialContexts: []string{credCtx},
		})
		if err != nil {
			return "", mcp.ServerConfig{}, false, fmt.Errorf("failed to list credentials for system server: %w", err)
		}

		secretToolName := systemmcpserver.SecretInfoToolName(systemServer.Name)
		for _, cred := range creds {
			// Skip the secret info credential — those vars go to the shim only, not the MCP server.
			if cred.ToolName == secretToolName {
				continue
			}
			credDetail, err := req.GPTClient.RevealCredential(req.Context(), []string{credCtx}, cred.ToolName)
			if err != nil {
				continue
			}
			maps.Copy(credEnv, credDetail.Env)
		}
	}

	// Retrieve the token exchange credential
	var secretsCred map[string]string
	tokenExchangeCred, err := req.GPTClient.RevealCredential(req.Context(), []string{systemServer.Name}, systemmcpserver.SecretInfoToolName(systemServer.Name))
	if err == nil {
		secretsCred = tokenExchangeCred.Env
	}

	baseURL := strings.TrimSuffix(req.APIBaseURL, "/api")
	audiences := systemServer.ValidConnectURLs(baseURL)

	serverConfig, _, err := mcp.SystemServerToServerConfig(systemServer, audiences, baseURL, credEnv, secretsCred)
	if err != nil {
		return "", mcp.ServerConfig{}, false, fmt.Errorf("failed to convert system server to config: %w", err)
	}

	mcpURL, transformedConfig, err := h.mcpSessionManager.LaunchServer(req.Context(), serverConfig)
	if err != nil {
		return "", mcp.ServerConfig{}, false, fmt.Errorf("failed to launch system MCP server: %w", err)
	}

	return mcpURL, transformedConfig, false, nil
}
