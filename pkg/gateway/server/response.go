package server

func (s *Server) authCompleteURL() string {
	if s.authCompleteURLOverride != "" {
		return s.authCompleteURLOverride
	}
	return s.uiURL + "/auth/oauth/complete"
}

// AuthCompleteURL returns the URL to redirect to after authentication completes.
// This is the public accessor for use by other packages (e.g., MCP OAuth handler).
func (s *Server) AuthCompleteURL() string {
	return s.authCompleteURL()
}
