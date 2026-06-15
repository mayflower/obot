package server

import (
	"context"

	"github.com/obot-platform/obot/pkg/accesscontrolrule"
	"github.com/obot-platform/obot/pkg/gateway/db"
	"github.com/obot-platform/obot/pkg/gateway/server/dispatcher"
	"github.com/obot-platform/obot/pkg/jwt/persistent"
	"github.com/obot-platform/obot/pkg/messagepolicy"
	"github.com/obot-platform/obot/pkg/modelaccesspolicy"
)

type Options struct {
	Hostname        string
	UIHostname      string `name:"ui-hostname" env:"OBOT_SERVER_UI_HOSTNAME"`
	AuthCompleteURL string `name:"auth-complete-url" env:"OBOT_SERVER_AUTH_COMPLETE_URL" usage:"Custom URL to redirect to after authentication completes (overrides default /login_complete)"`
	GatewayDebug    bool

	DailyUserInputTokenLimit  int `usage:"The maximum number of daily user input tokens to allow, < 0 disables the limit" default:"10000000"` // default is 10 million
	DailyUserOutputTokenLimit int `usage:"The maximum number of daily user output tokens to allow, < 0 disables the limit" default:"100000"`  // default is 100 thousand
}

type Server struct {
	db                        *db.DB
	baseURL, uiURL            string
	authCompleteURLOverride   string
	tokenService              *persistent.TokenService
	dispatcher                *dispatcher.Dispatcher
	acrHelper                 *accesscontrolrule.Helper
	mapHelper                 *modelaccesspolicy.Helper
	messagePolicyHelper       *messagepolicy.Helper
	dailyUserInputTokenLimit  int
	dailyUserOutputTokenLimit int
}

func New(ctx context.Context, db *db.DB, tokenService *persistent.TokenService, modelProviderDispatcher *dispatcher.Dispatcher, acrHelper *accesscontrolrule.Helper, mapHelper *modelaccesspolicy.Helper, messagePolicyHelper *messagepolicy.Helper, opts Options) (*Server, error) {
	s := &Server{
		db:                        db,
		baseURL:                   opts.Hostname,
		uiURL:                     opts.UIHostname,
		authCompleteURLOverride:   opts.AuthCompleteURL,
		tokenService:              tokenService,
		dispatcher:                modelProviderDispatcher,
		acrHelper:                 acrHelper,
		mapHelper:                 mapHelper,
		messagePolicyHelper:       messagePolicyHelper,
		dailyUserInputTokenLimit:  opts.DailyUserInputTokenLimit,
		dailyUserOutputTokenLimit: opts.DailyUserOutputTokenLimit,
	}

	go s.autoCleanupTokens(ctx)

	return s, nil
}
