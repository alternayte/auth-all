// Command example-app shows a complete Auth-All integration in a small Go
// application. It uses SQLite, email and password authentication, GitHub and
// Google sign-in, the Magic Link plugin, the passkeys plugin, and the OAuth
// provider plugin, which authorizes MCP clients for the /mcp endpoint.
//
// Run the migration before the first start:
//
//	go run ./cmd/auth-all migrate --driver sqlite --dsn file:example.db
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/oauth/github"
	"github.com/alternayte/auth-all/oauth/google"
	"github.com/alternayte/auth-all/plugins/magiclink"
	"github.com/alternayte/auth-all/plugins/oauthprovider"
	"github.com/alternayte/auth-all/plugins/passkeys"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store/sqlite"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	db, err := sqlite.Open("file:example.db")
	if err != nil {
		return err
	}
	defer db.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	appURL := envOr("APP_URL", "http://localhost:8080")
	key, err := keyEncryptionKey(logger)
	if err != nil {
		return err
	}
	// The MCP endpoint is a protected resource. An MCP client names it with
	// the resource parameter, and its access token carries it as aud.
	mcpResource := appURL + "/mcp"
	provider := oauthprovider.New(
		oauthprovider.KeyEncryptionKey(key),
		oauthprovider.LoginPath("/oauth"),
		oauthprovider.ConsentPath("/oauth"),
		oauthprovider.Scopes(oauthprovider.ScopeOpenID, oauthprovider.ScopeEmail,
			oauthprovider.ScopeOfflineAccess, "mcp"),
		oauthprovider.Resources(oauthprovider.Resource{
			Identifier: mcpResource,
			Scopes:     []string{"mcp", oauthprovider.ScopeOfflineAccess},
		}),
		// Claude and ChatGPT prefer a Client ID Metadata Document. An
		// older client registers dynamically.
		oauthprovider.AllowClientIDMetadataDocuments(oauthprovider.CIMDOptions{}),
		oauthprovider.AllowDynamicRegistration(),
	)

	auth, err := authall.New(
		authall.WithStore(sqlite.New(db)),
		authall.WithBaseURL(appURL),
		authall.WithEmailPassword(authall.EmailPasswordOptions{
			RequireEmailVerification: true,
		}),
		authall.WithEmailSender(consoleSender{logger: logger}),
		authall.WithProvider(github.New(
			github.WithClientID(os.Getenv("GITHUB_CLIENT_ID")),
			github.WithClientSecret(os.Getenv("GITHUB_CLIENT_SECRET")),
		)),
		authall.WithProvider(google.New(
			google.WithClientID(os.Getenv("GOOGLE_CLIENT_ID")),
			google.WithClientSecret(os.Getenv("GOOGLE_CLIENT_SECRET")),
		)),
		authall.WithPlugins(
			magiclink.New(magiclink.WithTTL(15*time.Minute)),
			// The RP ID and the origin come from APP_URL. A passkey binds
			// to a domain, so open the example at localhost, not 127.0.0.1.
			passkeys.New(passkeys.RPDisplayName("Auth-All example")),
			provider,
		),
		authall.WithRateLimiter(ratelimit.NewMemory(20, time.Minute)),
		authall.WithLogger(logger),
		authall.WithEventHandler(events.HandlerFunc(func(_ context.Context, ev events.Event) {
			logger.Info("auth event", "name", string(ev.Name), "user", ev.UserID)
		})),
	)
	if err != nil {
		return err
	}
	// The application decides when the schema changes. Auth-All never migrates
	// a database on its own.
	if err := auth.CheckSchema(context.Background()); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", auth.Handler())
	// The verification email points at this page. The page consumes the token
	// through the programmatic API, so the application controls the result.
	mux.HandleFunc("GET /verify-email", func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.VerifyEmailToken(r.Context(), r.URL.Query().Get("token"))
		if err != nil {
			http.Error(w, "The verification link is invalid or expired.", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "The address %s is verified. You can sign in now.\n", user.Email)
	})
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		user, err := auth.User(r.Context(), r)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if user == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, "Signed in as %s\n", user.Email)
	})

	// RFC 8414 and RFC 9728 put the metadata at the origin root.
	mux.Handle("/.well-known/", provider.MetadataHandler())
	resourceMetadata := provider.ProtectedResourceHandler(mcpResource)
	mux.Handle("/.well-known/oauth-protected-resource", resourceMetadata)
	mux.Handle("/.well-known/oauth-protected-resource/", resourceMetadata)
	// The MCP endpoint takes an access token for this resource with the mcp
	// scope. A request without one gets 401 and the metadata URL, which is
	// how an MCP client finds the authorization server.
	mux.Handle("/mcp", provider.RequireAudience(mcpResource, http.HandlerFunc(serveMCP),
		oauthprovider.RequireAudienceOptions{Scopes: []string{"mcp"}}))
	// One page serves sign-in and consent for the OAuth provider.
	mux.HandleFunc("GET /oauth", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(oauthPage))
	})

	// A small page drives the passkey ceremonies in the browser.
	mux.HandleFunc("GET /passkeys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(passkeyPage))
	})

	address := envOr("ADDRESS", ":8080")
	logger.Info("listening", "address", address)
	return http.ListenAndServe(address, mux)
}

// consoleSender prints the message the application must deliver. A production
// application sends the message through its own provider.
type consoleSender struct{ logger *slog.Logger }

func (c consoleSender) Send(_ context.Context, msg email.Message) error {
	c.logger.Info("send email", "intent", string(msg.Intent), "to", msg.To, "url", msg.URL)
	return nil
}

// serveMCP answers a JSON-RPC call with the caller and the granted scopes. A
// real MCP server dispatches the call to its tools here.
func serveMCP(w http.ResponseWriter, r *http.Request) {
	p := authall.PrincipalFrom(r.Context())
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"result": map[string]any{
			"user":   p.User.Email,
			"client": p.OAuth.ClientID,
			"scopes": p.OAuth.Scopes,
		},
	})
}

// developmentKey wraps the signing keys when OAUTH_KEY is not set. It is
// public, so a deployment sets its own key.
const developmentKey = "ZGV2ZWxvcG1lbnQta2V5LW9mLXRoZS1leGFtcGxlISE="

// keyEncryptionKey reads the 32-byte key that wraps the OAuth signing keys
// from OAUTH_KEY, in standard base64.
func keyEncryptionKey(logger *slog.Logger) ([]byte, error) {
	raw := os.Getenv("OAUTH_KEY")
	if raw == "" {
		logger.Warn("OAUTH_KEY is not set, so the example uses its public development key")
		raw = developmentKey
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("OAUTH_KEY must be 32 bytes in standard base64")
	}
	return key, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
