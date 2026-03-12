package oauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	apitypes "github.com/obot-platform/obot/apiclient/types"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
)

type completionRedirectValidator struct {
	allowlist []*url.URL
}

func newCompletionRedirectValidator(allowlist []string) (*completionRedirectValidator, error) {
	result := &completionRedirectValidator{
		allowlist: make([]*url.URL, 0, len(allowlist)),
	}

	for _, raw := range allowlist {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		u, err := parseAbsoluteHTTPURL(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid MCP OAuth return URL allowlist entry %q: %w", raw, err)
		}

		result.allowlist = append(result.allowlist, u)
	}

	return result, nil
}

func (v *completionRedirectValidator) Validate(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	u, err := parseAbsoluteHTTPURL(raw)
	if err != nil {
		return "", apitypes.NewErrHTTP(http.StatusBadRequest, "return_url must be an absolute http or https URL")
	}

	for _, allowed := range v.allowlist {
		if matchesAllowedReturnURL(u, allowed) {
			return u.String(), nil
		}
	}

	return "", apitypes.NewErrHTTP(http.StatusBadRequest, "return_url is not allowed")
}

func parseAbsoluteHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if !u.IsAbs() || u.Host == "" {
		return nil, fmt.Errorf("URL must be absolute")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL scheme must be http or https")
	}
	return u, nil
}

func matchesAllowedReturnURL(candidate, allowed *url.URL) bool {
	if !strings.EqualFold(candidate.Scheme, allowed.Scheme) || !strings.EqualFold(candidate.Host, allowed.Host) {
		return false
	}

	allowedPath := allowed.EscapedPath()
	candidatePath := candidate.EscapedPath()
	if allowedPath == "" {
		allowedPath = "/"
	}
	if candidatePath == "" {
		candidatePath = "/"
	}

	if allowedPath == "/" {
		return true
	}
	if candidatePath == allowedPath {
		return true
	}
	if strings.HasSuffix(allowedPath, "/") {
		return strings.HasPrefix(candidatePath, allowedPath)
	}
	return strings.HasPrefix(candidatePath, allowedPath+"/")
}

func appendReturnURL(rawURL, returnURL string) string {
	if strings.TrimSpace(returnURL) == "" {
		return rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	q := u.Query()
	q.Set("return_url", returnURL)
	u.RawQuery = q.Encode()
	return u.String()
}

func uiOAuthCompletionRedirect(defaultRedirectURL, completionRedirectURL string, server v1.MCPServer) string {
	if server.Spec.CompositeName != "" {
		return defaultRedirectURL
	}
	if completionRedirectURL != "" {
		return completionRedirectURL
	}
	return defaultRedirectURL
}
