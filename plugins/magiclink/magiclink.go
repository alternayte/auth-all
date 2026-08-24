// Package magiclink implements sign-in through an emailed one-time link.
//
// The plugin uses only the public plugin package. It receives no privileged
// access to Auth-All internals, so a third-party plugin can do the same work.
package magiclink

import (
	"html/template"
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

// confirmationPage is the page that GET /magic-link/verify returns.
//
// The page carries no third-party asset and no script, so a strict content
// security policy blocks nothing. A mail scanner that pre-fetches the link
// receives this page and submits no form, so the one-time token survives.
var confirmationPage = template.Must(template.New("magic-link-confirm").Parse(
	`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Confirm the sign-in</title>
</head>
<body>
<main>
<h1>Confirm the sign-in</h1>
<p>Select the button to sign in as {{.Email}}.</p>
<p>Do not select the button if you did not ask for this link.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="token" value="{{.Token}}">
<input type="hidden" name="callbackURL" value="{{.CallbackURL}}">
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>
`))

// confirmationData fills the confirmation page.
type confirmationData struct {
	Email       string
	Action      string
	Token       string
	CallbackURL string
}

// Plugin is the Magic Link plugin.
type Plugin struct {
	ttl         time.Duration
	createUser  bool
	callbackURL string
	verifyURL   string
	noConfirm   bool
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

// WithoutConfirmation lets GET /magic-link/verify complete the sign-in on its
// own. The default needs the confirmation step.
//
// Do not use this option unless you accept three risks. An attacker can make
// the browser of another person open a link and sign that person in to the
// account of the attacker. The token reaches the callback host through the
// Referer header. A mail scanner that pre-fetches the link consumes the token,
// so the person can no longer sign in.
func WithoutConfirmation() Option { return func(p *Plugin) { p.noConfirm = true } }

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

	r.OpenAPISchema("MagicLinkVerifyResponse", openapi.Object(
		[]string{"redirectTo"},
		map[string]*openapi.Schema{"redirectTo": openapi.String()}))

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
		Handler: http.HandlerFunc(p.handleVerifyGet),
		Operation: &openapi.Operation{
			OperationID: "magicLinkConfirmation",
			Summary:     "Return the confirmation page of a sign-in link",
			Description: "The page carries a form that posts to the same path. " +
				"The endpoint creates no session and consumes no token.",
			Tags: tag,
			Parameters: []openapi.Parameter{
				{Name: "token", In: "query", Required: true, Schema: openapi.String()},
				{Name: "callbackURL", In: "query", Schema: openapi.String()},
			},
			Responses: map[string]openapi.Response{
				"200": {Description: "The confirmation page"},
				"400": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
			},
		},
	})

	r.Route(plugin.Route{
		Method:  http.MethodPost,
		Path:    "/magic-link/verify",
		Handler: http.HandlerFunc(p.handleVerifyPost),
		Operation: &openapi.Operation{
			OperationID: "magicLinkVerify",
			Summary:     "Complete a sign-in with a link token",
			Tags:        tag,
			RequestBody: openapi.JSONBody(openapi.Object([]string{"token"}, map[string]*openapi.Schema{
				"token":       openapi.String(),
				"callbackURL": openapi.String(),
			})),
			Description: "A JSON request receives the redirect target in the body. " +
				"A form submission receives a 303 redirect, which is what the confirmation page needs.",
			Responses: map[string]openapi.Response{
				"200": openapi.JSONResponse("The sign-in is complete", openapi.Ref("MagicLinkVerifyResponse")),
				"303": {Description: "A redirect back to the application"},
				"400": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
				"403": openapi.JSONResponse("Auth-All error", openapi.Ref("ErrorResponse")),
			},
			Client: &openapi.ClientBinding{Namespace: "magicLink", Method: "verify"},
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

// setLinkHeaders keeps a sign-in link out of a cache and out of a Referer
// header. The token sits in the query string, so a leak of the referrer leaks
// the token.
func setLinkHeaders(w http.ResponseWriter) {
	head := w.Header()
	head.Set("Referrer-Policy", "no-referrer")
	head.Set("Cache-Control", "no-store")
	head.Set("Pragma", "no-cache")
}

// verifyPath returns the path that the confirmation form posts to.
func (p *Plugin) verifyPath() string { return p.svc.BasePath() + "/magic-link/verify" }

// handleVerifyGet returns the confirmation page.
//
// The page exists for three reasons. A GET that signs a person in accepts a
// login cross-site request forgery. The token reaches the callback host
// through the Referer header. A mail scanner that pre-fetches the link
// consumes the one-time token. A scanner submits no form, so the token
// survives.
func (p *Plugin) handleVerifyGet(w http.ResponseWriter, r *http.Request) {
	setLinkHeaders(w)
	if p.noConfirm {
		p.completeVerify(w, r, r.URL.Query().Get("token"), r.URL.Query().Get("callbackURL"), false)
		return
	}
	httpSvc := p.svc.HTTP()
	token := r.URL.Query().Get("token")
	tok, err := p.svc.Tokens().Peek(r.Context(), TokenKind, token)
	if err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	data := confirmationData{
		Email:       tok.Identifier,
		Action:      p.verifyPath(),
		Token:       token,
		CallbackURL: httpSvc.SafeRedirect(r.URL.Query().Get("callbackURL"), ""),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := confirmationPage.Execute(w, data); err != nil {
		p.svc.Logger().Error("magiclink: cannot write the confirmation page", "error", err.Error())
	}
}

// verifyRequest is the JSON body of the confirmation step.
type verifyRequest struct {
	Token       string `json:"token"`
	CallbackURL string `json:"callbackURL"`
}

// handleVerifyPost completes the sign-in. It runs the origin check, so a
// forged cross-site submission fails.
func (p *Plugin) handleVerifyPost(w http.ResponseWriter, r *http.Request) {
	setLinkHeaders(w)
	httpSvc := p.svc.HTTP()
	if err := httpSvc.CheckOrigin(r); err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	var req verifyRequest
	wantJSON := strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
	if wantJSON {
		if err := httpSvc.DecodeJSON(r, &req); err != nil {
			httpSvc.WriteError(w, err)
			return
		}
	} else {
		// The confirmation page submits a plain HTML form.
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			httpSvc.WriteError(w, apierr.ErrInvalidRequest)
			return
		}
		req.Token = r.PostFormValue("token")
		req.CallbackURL = r.PostFormValue("callbackURL")
	}
	p.completeVerify(w, r, req.Token, req.CallbackURL, wantJSON)
}

// maxFormBytes bounds the body of the confirmation form.
const maxFormBytes = 1 << 16

// completeVerify consumes the token, proves the address, and issues a session.
//
// A browser submits the confirmation form and must follow a redirect. A client
// that sends JSON wants the target in the body, so asJSON selects the answer.
func (p *Plugin) completeVerify(w http.ResponseWriter, r *http.Request, token, callbackURL string, asJSON bool) {
	ctx := r.Context()
	httpSvc := p.svc.HTTP()
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
	// A used link proves that the person controls the address. An unverified
	// address can carry a password and a session that somebody else planted, so
	// the proof removes both before the plugin issues the new session.
	if err := p.svc.Users().ProveEmailOwnership(ctx, user.ID); err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	if _, err := p.svc.Sessions().Issue(ctx, w, r, user, ID); err != nil {
		httpSvc.WriteError(w, err)
		return
	}
	p.svc.Events().Emit(ctx, events.MagicLinkUsed, user.ID, nil)
	fallback := p.callbackURL
	if fallback == "" {
		fallback = p.svc.BaseURL()
	}
	target := httpSvc.SafeRedirect(callbackURL, fallback)
	if target == "" {
		target = "/"
	}
	if asJSON {
		httpSvc.WriteJSON(w, http.StatusOK, map[string]string{"redirectTo": target})
		return
	}
	// The browser must follow the redirect with a GET, so the status is 303.
	http.Redirect(w, r, target, http.StatusSeeOther)
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
