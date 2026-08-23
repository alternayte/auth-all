// Package reference builds the canonical Auth-All configuration.
//
// The configuration enables every first-party v1 capability. The command line
// tool uses it to emit the schema, the OpenAPI contract, and the generated
// TypeScript client, so the published artifacts describe the complete v1 API.
package reference

import (
	"context"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/oauth/github"
	"github.com/alternayte/auth-all/oauth/google"
	"github.com/alternayte/auth-all/plugins/magiclink"
	"github.com/alternayte/auth-all/store"
	"github.com/alternayte/auth-all/store/sqlite"
)

// BaseURL is the placeholder application URL of the reference configuration.
const BaseURL = "https://app.example.com"

// noopSender satisfies the email boundary of the reference configuration. The
// reference instance never sends a message, because it only describes the API.
type noopSender struct{}

func (noopSender) Send(context.Context, email.Message) error { return nil }

// Options returns the option list of the canonical configuration.
func Options(s store.Store) []authall.Option {
	return []authall.Option{
		authall.WithStore(s),
		authall.WithBaseURL(BaseURL),
		authall.WithEmailPassword(authall.EmailPasswordOptions{SendVerificationOnSignUp: true}),
		authall.WithEmailSender(noopSender{}),
		authall.WithProvider(github.New(
			github.WithClientID("reference-client-id"),
			github.WithClientSecret("reference-client-secret"),
		)),
		authall.WithProvider(google.New(
			google.WithClientID("reference-client-id"),
			google.WithClientSecret("reference-client-secret"),
		)),
		authall.WithPlugins(magiclink.New(magiclink.WithTTL(15 * time.Minute))),
	}
}

// New returns the canonical Auth-All instance over a temporary in-memory
// database. It never writes to an application database.
func New() (*authall.Auth, error) {
	db, err := sqlite.Open("file:auth-all-reference?mode=memory&cache=shared")
	if err != nil {
		return nil, err
	}
	return authall.New(Options(sqlite.New(db))...)
}

// NewWithStore returns the canonical Auth-All instance over one store.
func NewWithStore(s store.Store) (*authall.Auth, error) {
	return authall.New(Options(s)...)
}
