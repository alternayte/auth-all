// Command example-app shows a complete Auth-All integration in a small Go
// application. It uses SQLite, email and password authentication, GitHub and
// Google sign-in, and the Magic Link plugin.
//
// Run the migration before the first start:
//
//	go run ./cmd/auth-all migrate --driver sqlite --dsn file:example.db
package main

import (
	"context"
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

	auth, err := authall.New(
		authall.WithStore(sqlite.New(db)),
		authall.WithBaseURL(envOr("APP_URL", "http://localhost:8080")),
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

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
