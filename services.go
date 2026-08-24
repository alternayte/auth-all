package authall

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// services implements plugin.Services. It is the complete extension surface a
// plugin receives. The official Magic Link plugin uses only this surface.
type services struct{ auth *Auth }

func (s *services) Store() store.Store              { return s.auth.cfg.store }
func (s *services) Email() email.Sender             { return s.auth.cfg.sender }
func (s *services) Events() *events.Emitter         { return s.auth.emitter }
func (s *services) Now() time.Time                  { return s.auth.cfg.now() }
func (s *services) BasePath() string                { return s.auth.cfg.basePath }
func (s *services) BaseURL() string                 { return s.auth.cfg.baseURL }
func (s *services) RateLimiter() ratelimit.Limiter  { return s.auth.cfg.limiter }
func (s *services) Logger() *slog.Logger            { return s.auth.cfg.logger }
func (s *services) Users() plugin.UserService       { return (*userService)(s) }
func (s *services) Sessions() plugin.SessionService { return (*sessionService)(s) }
func (s *services) Tokens() plugin.TokenService     { return (*tokenService)(s) }
func (s *services) HTTP() plugin.HTTPService        { return (*httpService)(s) }

type userService services

func (u *userService) ByID(ctx context.Context, id string) (*store.User, error) {
	return u.auth.GetUser(ctx, id)
}

func (u *userService) ByEmail(ctx context.Context, address string) (*store.User, error) {
	return u.auth.GetUserByEmail(ctx, address)
}

func (u *userService) Create(ctx context.Context, in plugin.CreateUserInput) (*store.User, error) {
	return u.auth.createUser(ctx, CreateUserInput{
		Email:         in.Email,
		DisplayName:   in.DisplayName,
		ImageURL:      in.ImageURL,
		EmailVerified: in.EmailVerified,
	}, "")
}

func (u *userService) MarkEmailVerified(ctx context.Context, userID string) error {
	return u.auth.markEmailVerified(ctx, userID)
}

func (u *userService) DeleteCredential(ctx context.Context, userID string) error {
	if err := u.auth.cfg.store.Users().DeleteCredential(ctx, userID); err != nil && !isNotFound(err) {
		return publicError(err)
	}
	return nil
}

func (u *userService) ProveEmailOwnership(ctx context.Context, userID string) error {
	return u.auth.proveEmailOwnership(ctx, userID, false)
}

type sessionService services

func (s *sessionService) Issue(ctx context.Context, w http.ResponseWriter, r *http.Request, user *store.User, method string) (*store.Session, error) {
	return s.auth.issueSession(ctx, w, r, user, method)
}

func (s *sessionService) Current(ctx context.Context, r *http.Request) (*store.Session, *store.User, error) {
	return s.auth.resolveSession(ctx, r)
}

func (s *sessionService) Revoke(ctx context.Context, sessionID string) error {
	return s.auth.RevokeSession(ctx, sessionID)
}

func (s *sessionService) RevokeAll(ctx context.Context, userID string) (int, error) {
	return s.auth.RevokeUserSessions(ctx, userID)
}

func (s *sessionService) Clear(w http.ResponseWriter) { s.auth.clearCookie(w) }

type tokenService services

func (t *tokenService) Issue(ctx context.Context, in plugin.IssueTokenInput) (string, *store.Token, error) {
	return t.auth.issueToken(ctx, in)
}

func (t *tokenService) Consume(ctx context.Context, kind, plaintext string) (*store.Token, error) {
	return t.auth.consumeToken(ctx, kind, plaintext)
}

func (t *tokenService) Peek(ctx context.Context, kind, plaintext string) (*store.Token, error) {
	return t.auth.peekToken(ctx, kind, plaintext)
}

type httpService services

func (h *httpService) CheckOrigin(r *http.Request) error { return h.auth.checkOrigin(r) }

func (h *httpService) DecodeJSON(r *http.Request, dst any) error { return h.auth.decodeJSON(r, dst) }

func (h *httpService) WriteJSON(w http.ResponseWriter, status int, body any) {
	h.auth.writeJSON(w, status, body)
}

func (h *httpService) WriteError(w http.ResponseWriter, err error) { h.auth.writeError(w, err) }

func (h *httpService) SafeRedirect(candidate, fallback string) string {
	return h.auth.safeRedirect(candidate, fallback)
}

func (h *httpService) ClientIP(r *http.Request) string { return h.auth.clientIP(r) }
