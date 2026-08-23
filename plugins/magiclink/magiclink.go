// Package magiclink implements sign-in through an emailed one-time link.
//
// The plugin uses only the public plugin package. It receives no privileged
// access to Auth-All internals, so a third-party plugin can do the same work.
package magiclink

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/ratelimit"
	"github.com/alternayte/auth-all/store"
)

// ID is the stable plugin identifier.
const ID = "magic-link"

// TokenKind is the one-time token namespace of this plugin.
const TokenKind = "magic-link"

// DefaultTTL is the default lifetime of a sign-in link.
const DefaultTTL = 15 * time.Minute

// messageSent is the enumeration-safe response of a link request.
const messageSent = "If the address can receive a sign-in link, one has been sent."

// Plugin is the Magic Link plugin.
type Plugin struct {
	ttl         time.Duration
	createUser  bool
	callbackURL string
	verifyURL   string
	svc         plugin.Services
}

// Option configures the plugin.
type Option func(*Plugin)

// WithTTL sets the lifetime of a sign-in link.
func WithTTL(d time.Duration) Option { return func(p *Plugin) { p.ttl = d } }

// WithCreateUser controls whether an unknown address creates an account. It is
// enabled by default, because a magic link proves ownership of the address.
func WithCreateUser(v bool) Option { return func(p *Plugin) { p.createUser = v } }

// WithCallbackURL sets where the browser goes after a successful sign-in. The
// default is the configured base URL.
func WithCallbackURL(v string) Option { return func(p *Plugin) { p.callbackURL = v } }

// WithVerifyURL overrides the absolute link that the email carries. The default
// is the verify endpoint of this plugin.
func WithVerifyURL(v string) Option { return func(p *Plugin) { p.verifyURL = v } }

// New returns the Magic Link plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{ttl: DefaultTTL, createUser: true}
	for _, o := range opts {
		o(p)
	}
	if p.ttl <= 0 {
		p.ttl = DefaultTTL
	}
	return p
}

// ID implements plugin.Plugin.
func (p *Plugin) ID() string { return ID }

// Register implements plugin.Plugin.
func (p *Plugin) Register(r *plugin.Registry) error {
	p.svc = r.Services()
	tag := []string{"magic-link"}

	r.Route(plugin.Route{
		Method:  http.MethodPost,
		Path:    "/magic-link/send",
		Handler: http.HandlerFunc(p.handleSend),
		Operation: &openapi.Operation{
			OperationID: "magicLinkSend",
			Summary:     "Send a sign-in link to an email address",
			Tags:        tag,
			RequestBody: openapi.JSONBody(openapi.Object([]string{"email"}, map[string]*openapi.Schema{
				"email":       openapi.String(),
				"callbackURL": openapi.String(),
			})),
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("An enumeration-safe acknowledgement", openapi.Ref("MessageResponse")),
				"400": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
				"429": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
			},
			Client: &openapi.ClientBinding{Namespace: "magicLink", Method: "send"},
		},
	})

	r.Route(plugin.Route{
		Method:  http.MethodGet,
		Path:    "/magic-link/verify",
		Handler: http.HandlerFunc(p.handleVerify),
		Operation: &openapi.Operation{
			OperationID: "magicLinkVerify",
			Summary:     "Complete a sign-in with a link token",
			Tags:        tag,
			Parameters: []openapi.Parameter{
				{Name: "token", In: "query", Required: true, Schema: openapi.String()},
				{Name: "callbackURL", In: "query", Schema: openapi.String()},
			},
			Responses: map[string]openapi.Response{
				"302": {Description: "A redirect back to the application"},
				"400": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
			},
			Client: &openapi.ClientBinding{Namespace: "magicLink", Method: "verify", Redirect: true},
		},
	})
	return nil
}

type sendRequest struct {
	Email       string `json:"email"`
	CallbackURL string `json:"callbackURL"`
}

func (p *Plugin) linkURL(token, callback string) string {
	base := p.verifyURL
	if base == "" {
		base = p.svc.BaseURL() + p.svc.BasePath() + "/magic-link/verify"
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	link := base + sep + "token=" + url.QueryEscape(token)
	if callback != "" {
		link += "&callbackURL=" + url.QueryEscape(callback)
	}
	return link
}

func (p *Plugin) handleSend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	httpSvc := p.svc.HTTP()
	if err := httpSvc.CheckOrigin(r); err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	var req sendRequest
	if err := httpSvc.DecodeJSON(r, &req); err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	normalized := email.Normalize(req.Email)
	ok, err := p.svc.RateLimiter().Allow(ctx, ratelimit.Key{
		Operation: ratelimit.OpMagicLinkRequest, IP: httpSvc.ClientIP(r), Email: normalized,
	})
	if err != nil {
		p.svc.Logger().Error("magiclink: the rate limiter failed", "error", err.Error())
	} else if !ok {
		httpSvc.WriteError(w, apierr.ErrRateLimited)
		return
	}

	// The response never discloses whether the address has an account.
	defer httpSvc.WriteJSON(w, http.StatusOK, map[string]string{"message": messageSent})

	if !email.Valid(normalized) {
		return
	}
	sender := p.svc.Email()
	if sender == nil {
		p.svc.Logger().Error("magiclink: a sign-in link needs an email sender")
		return
	}
	var userID *string
	user, err := p.svc.Users().ByEmail(ctx, normalized)
	if err == nil && user != nil {
		userID = &user.ID
	} else if !p.createUser {
		// The plugin does not create accounts, so an unknown address gets no
		// link. The response stays the same.
		return
	}
	token, tok, err := p.svc.Tokens().Issue(ctx, plugin.IssueTokenInput{
		Kind:            TokenKind,
		UserID:          userID,
		Identifier:      normalized,
		TTL:             p.ttl,
		ReplaceExisting: true,
	})
	if err != nil {
		p.svc.Logger().Error("magiclink: cannot issue a token", "error", err.Error())
		return
	}
	callback := httpSvc.SafeRedirect(req.CallbackURL, p.callbackURL)
	msg := email.Message{
		Intent:    email.IntentMagicLink,
		To:        normalized,
		Token:     token,
		URL:       p.linkURL(token, callback),
		ExpiresAt: tok.ExpiresAt,
	}
	if userID != nil {
		msg.UserID = *userID
		msg.To = user.Email
	}
	if err := sender.Send(ctx, msg); err != nil {
		p.svc.Logger().Error("magiclink: cannot send the message", "error", err.Error())
		return
	}
	emitted := ""
	if userID != nil {
		emitted = *userID
	}
	p.svc.Events().Emit(ctx, events.MagicLinkRequested, emitted, nil)
}

func (p *Plugin) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	httpSvc := p.svc.HTTP()
	token := r.URL.Query().Get("token")
	tok, err := p.svc.Tokens().Consume(ctx, TokenKind, token)
	if err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	user, err := p.resolveUser(r, tok.UserID, tok.Identifier)
	if err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	if _, err := p.svc.Sessions().Issue(ctx, w, r, user, ID); err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	// A successful link proves that the user controls the address.
	if err := p.svc.Users().MarkEmailVerified(ctx, user.ID); err != nil {
		p.svc.Logger().Error("magiclink: cannot mark the address as verified", "error", err.Error())
	}
	p.svc.Events().Emit(ctx, events.MagicLinkUsed, user.ID, nil)
	fallback := p.callbackURL
	if fallback == "" {
		fallback = p.svc.BaseURL()
	}
	target := httpSvc.SafeRedirect(r.URL.Query().Get("callbackURL"), fallback)
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (p *Plugin) resolveUser(r *http.Request, userID *string, identifier string) (*store.User, error) {
	ctx := r.Context()
	if userID != nil {
		user, err := p.svc.Users().ByID(ctx, *userID)
		if err != nil {
			return nil, apierr.ErrInvalidToken
		}
		return user, nil
	}
	if user, err := p.svc.Users().ByEmail(ctx, identifier); err == nil && user != nil {
		return user, nil
	}
	if !p.createUser {
		return nil, apierr.ErrInvalidToken
	}
	user, err := p.svc.Users().Create(ctx, plugin.CreateUserInput{
		Email:         identifier,
		EmailVerified: true,
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}
