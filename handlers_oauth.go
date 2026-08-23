package authall

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/oauth"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/store"
)

func (a *Auth) registerOAuthRoutes() {
	tag := []string{"oauth"}
	providerParam := openapi.Parameter{
		Name: "provider", In: "path", Required: true,
		Description: "The configured provider id, for example github.",
		Schema:      openapi.String(),
	}

	authorize := operation("oauthAuthorize", "Start a provider sign-in", tag, nil,
		"A redirect to the provider", nil,
		&openapi.ClientBinding{Namespace: "oauth", Method: "authorize", Redirect: true}, "404")
	authorize.Parameters = []openapi.Parameter{providerParam, {
		Name: "redirect_to", In: "query", Description: "Where to send the browser after success.",
		Schema: openapi.String(),
	}}
	authorize.Responses["302"] = openapi.Response{Description: "A redirect to the provider"}
	delete(authorize.Responses, "200")
	a.handle(http.MethodGet, "/oauth/{provider}", a.handleOAuthStart, authorize)

	callback := operation("oauthCallback", "Complete a provider sign-in", tag, nil,
		"A redirect back to the application", nil,
		&openapi.ClientBinding{Namespace: "oauth", Method: "callback", Redirect: true}, "400", "404", "409")
	callback.Parameters = []openapi.Parameter{providerParam,
		{Name: "code", In: "query", Schema: openapi.String()},
		{Name: "state", In: "query", Schema: openapi.String()},
	}
	callback.Responses["302"] = openapi.Response{Description: "A redirect back to the application"}
	delete(callback.Responses, "200")
	a.handle(http.MethodGet, "/oauth/{provider}/callback", a.handleOAuthCallback, callback)

	accountTag := []string{"account"}
	a.handle(http.MethodGet, "/account/providers", a.handleAccountProviders, operation(
		"accountProviders", "List the authentication methods of the current user", accountTag, nil,
		"The linked providers", openapi.Ref("ProvidersResponse"),
		&openapi.ClientBinding{Namespace: "account", Method: "providers"}, "401"))

	link := operation("accountLink", "Start an explicit provider link", accountTag, nil,
		"The provider authorization URL", openapi.Ref("LinkResponse"),
		&openapi.ClientBinding{Namespace: "account", Method: "link"}, "401", "404")
	link.Parameters = []openapi.Parameter{providerParam}
	a.handle(http.MethodPost, "/account/link/{provider}", a.handleAccountLink, link)

	unlink := operation("accountUnlink", "Remove a linked provider", accountTag, nil,
		"The provider is unlinked", openapi.Ref("SuccessResponse"),
		&openapi.ClientBinding{Namespace: "account", Method: "unlink"}, "401", "404", "409")
	unlink.Parameters = []openapi.Parameter{providerParam}
	a.handle(http.MethodPost, "/account/unlink/{provider}", a.handleAccountUnlink, unlink)
}

func (a *Auth) provider(id string) (oauth.Provider, error) {
	p, ok := a.providers[id]
	if !ok {
		return nil, apierr.ErrProviderNotFound
	}
	return p, nil
}

// callbackURI returns the registered redirect URI of one provider. Auth-All
// always sends its own callback URL, so a provider cannot be told to redirect
// somewhere else.
func (a *Auth) callbackURI(providerID string) string {
	return a.cfg.baseURL + a.cfg.basePath + "/oauth/" + providerID + "/callback"
}

// startOAuth stores the state, the PKCE verifier, and the nonce, and returns
// the provider authorization URL.
func (a *Auth) startOAuth(ctx context.Context, w http.ResponseWriter, p oauth.Provider, redirectTo string, linkUserID *string) (string, error) {
	state, err := crypto.NewToken()
	if err != nil {
		return "", apierr.ErrInternal.WithCause(err)
	}
	nonce, err := crypto.NewToken()
	if err != nil {
		return "", apierr.ErrInternal.WithCause(err)
	}
	verifier := ""
	challenge := ""
	if p.SupportsPKCE() {
		verifier, err = crypto.NewPKCEVerifier()
		if err != nil {
			return "", apierr.ErrInternal.WithCause(err)
		}
		challenge = crypto.PKCEChallenge(verifier)
	}
	now := a.cfg.now()
	record := &store.OAuthState{
		ID:         uuid.NewString(),
		StateHash:  crypto.HashToken(state),
		Provider:   p.ID(),
		Verifier:   verifier,
		Nonce:      nonce,
		RedirectTo: redirectTo,
		LinkUserID: linkUserID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(a.cfg.tokenTTL.OAuthState),
	}
	if err := a.cfg.store.OAuthStates().Create(ctx, record); err != nil {
		return "", apierr.ErrInternal.WithCause(err)
	}
	url, err := p.AuthCodeURL(oauth.AuthRequest{
		State:         state,
		RedirectURI:   a.callbackURI(p.ID()),
		CodeChallenge: challenge,
		Nonce:         nonce,
	})
	if err != nil {
		return "", apierr.ErrInternal.WithCause(err)
	}
	// The state cookie binds the pending request to this browser. Only the
	// browser that started the flow can complete it, so a state that an
	// attacker obtained cannot be finished in the browser of another person.
	a.setOAuthStateCookie(w, state, record.ExpiresAt)
	return url, nil
}

// oauthStateCookieName returns the name of the short-lived binding cookie.
func (a *Auth) oauthStateCookieName() string { return a.cfg.cookie.Name + ".oauth_state" }

// setOAuthStateCookie writes the binding cookie of one pending OAuth request.
func (a *Auth) setOAuthStateCookie(w http.ResponseWriter, state string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.oauthStateCookieName(),
		Value:    state,
		Path:     a.cfg.cookie.Path,
		Domain:   a.cfg.cookie.Domain,
		Expires:  expires,
		HttpOnly: true,
		Secure:   a.cookieSecure(),
		// The provider returns the browser with a top-level navigation, which
		// carries a cookie of this policy.
		SameSite: http.SameSiteLaxMode,
	})
}

// clearOAuthStateCookie removes the binding cookie.
func (a *Auth) clearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.oauthStateCookieName(),
		Value:    "",
		Path:     a.cfg.cookie.Path,
		Domain:   a.cfg.cookie.Domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
	})
}

// requestBindsState reports whether the request carries the binding cookie of
// the state it presents.
func (a *Auth) requestBindsState(r *http.Request, state string) bool {
	cookie, err := r.Cookie(a.oauthStateCookieName())
	if err != nil || cookie.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) == 1
}

func (a *Auth) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := a.provider(r.PathValue("provider"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	redirectTo := a.safeRedirect(r.URL.Query().Get("redirect_to"), a.cfg.baseURL)
	url, err := a.startOAuth(ctx, w, p, redirectTo, nil)
	if err != nil {
		a.writeError(w, err)
		return
	}
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *Auth) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := a.provider(r.PathValue("provider"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	query := r.URL.Query()
	if providerErr := query.Get("error"); providerErr != "" {
		a.writeError(w, apierr.ErrOAuthFailed)
		return
	}
	state := query.Get("state")
	code := query.Get("code")
	if state == "" || code == "" {
		a.writeError(w, apierr.ErrOAuthStateInvalid)
		return
	}
	// The browser that completes the flow must be the browser that started it.
	if !a.requestBindsState(r, state) {
		a.clearOAuthStateCookie(w)
		a.writeError(w, apierr.ErrOAuthStateInvalid)
		return
	}
	a.clearOAuthStateCookie(w)
	record, err := a.cfg.store.OAuthStates().Consume(ctx, crypto.HashToken(state), a.cfg.now())
	if err != nil {
		if isNotFound(err) {
			a.writeError(w, apierr.ErrOAuthStateInvalid)
			return
		}
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	if record.Provider != p.ID() {
		a.writeError(w, apierr.ErrOAuthStateInvalid)
		return
	}
	if record.LinkUserID != nil {
		// A link completes only for the authenticated user that started it.
		_, current, err := a.resolveSession(ctx, r)
		if err != nil {
			a.writeError(w, err)
			return
		}
		if current == nil || current.ID != *record.LinkUserID {
			a.writeError(w, apierr.ErrUnauthorized.WithMessage(
				"Sign in again and start the provider link from your account."))
			return
		}
	}
	identity, err := p.Exchange(ctx, oauth.ExchangeRequest{
		Code:         code,
		RedirectURI:  a.callbackURI(p.ID()),
		CodeVerifier: record.Verifier,
		Nonce:        record.Nonce,
	})
	if err != nil {
		if errors.Is(err, oauth.ErrProviderRejected) {
			a.writeError(w, apierr.ErrOAuthFailed.WithCause(err))
			return
		}
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	if identity == nil || identity.ProviderAccountID == "" {
		a.writeError(w, apierr.ErrOAuthFailed)
		return
	}
	user, err := a.resolveOAuthUser(ctx, p.ID(), identity, record)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if _, err := a.issueSession(ctx, w, r, user, p.ID()); err != nil {
		a.writeError(w, err)
		return
	}
	a.emitter.Emit(ctx, events.OAuthCompleted, user.ID, map[string]any{"provider": p.ID()})
	http.Redirect(w, r, a.safeRedirect(record.RedirectTo, a.cfg.baseURL), http.StatusFound)
}

// resolveOAuthUser applies the account linking policy of Auth-All.
func (a *Auth) resolveOAuthUser(ctx context.Context, providerID string, identity *oauth.Identity, state *store.OAuthState) (*store.User, error) {
	accounts := a.cfg.store.Accounts()
	existingAccount, err := accounts.GetByProviderAccount(ctx, providerID, identity.ProviderAccountID)
	if err != nil && !isNotFound(err) {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	if existingAccount != nil {
		if state.LinkUserID != nil && *state.LinkUserID != existingAccount.UserID {
			return nil, apierr.ErrAccountAlreadyLinked
		}
		user, err := a.cfg.store.Users().GetByID(ctx, existingAccount.UserID)
		if err != nil {
			return nil, publicError(err)
		}
		return user, nil
	}

	if state.LinkUserID != nil {
		user, err := a.cfg.store.Users().GetByID(ctx, *state.LinkUserID)
		if err != nil {
			return nil, publicError(err)
		}
		if err := a.linkAccount(ctx, user, providerID, identity.ProviderAccountID); err != nil {
			return nil, err
		}
		return user, nil
	}

	normalized := email.Normalize(identity.Email)
	if normalized == "" {
		return nil, apierr.ErrOAuthFailed.WithMessage("The provider did not supply an email address.")
	}
	existingUser, err := a.cfg.store.Users().GetByNormalizedEmail(ctx, normalized)
	if err != nil && !isNotFound(err) {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	if existingUser != nil {
		// A matching email address alone never links an account. Auto-linking
		// requires an explicit opt-in and a verified address on both sides.
		if !a.cfg.linking.AllowVerifiedEmailAutoLink || !identity.EmailVerified || existingUser.EmailVerifiedAt == nil {
			return nil, apierr.ErrEmailAlreadyExists.WithMessage(
				"An account with this email address already exists. Sign in and link the provider.")
		}
		if err := a.linkAccount(ctx, existingUser, providerID, identity.ProviderAccountID); err != nil {
			return nil, err
		}
		return existingUser, nil
	}
	return a.createUserWithAccount(ctx, identity, providerID, normalized)
}

// linkAccount adds one provider identity to a user.
func (a *Auth) linkAccount(ctx context.Context, user *store.User, providerID, providerAccountID string) error {
	now := a.cfg.now()
	account := &store.Account{
		ID:                uuid.NewString(),
		UserID:            user.ID,
		Provider:          providerID,
		ProviderAccountID: providerAccountID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := a.cfg.store.Accounts().Create(ctx, account); err != nil {
		if isConflict(err) {
			return apierr.ErrAccountAlreadyLinked
		}
		return apierr.ErrInternal.WithCause(err)
	}
	a.hooks.RunAfterAccountLink(ctx, &hook.AccountLink{User: user, Account: account})
	a.emitter.Emit(ctx, events.AccountLinked, user.ID, map[string]any{"provider": providerID})
	return nil
}

// createUserWithAccount creates the user and the provider account atomically.
func (a *Auth) createUserWithAccount(ctx context.Context, identity *oauth.Identity, providerID, normalized string) (*store.User, error) {
	now := a.cfg.now()
	user := &store.User{
		ID:              uuid.NewString(),
		Email:           identity.Email,
		EmailNormalized: normalized,
		DisplayName:     identity.DisplayName,
		ImageURL:        identity.ImageURL,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if identity.EmailVerified {
		verified := now
		user.EmailVerifiedAt = &verified
	}
	account := &store.Account{
		ID:                uuid.NewString(),
		UserID:            user.ID,
		Provider:          providerID,
		ProviderAccountID: identity.ProviderAccountID,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	ev := &hook.UserCreate{User: user}
	err := a.cfg.store.Transaction(ctx, func(tx store.Store) error {
		ev.Tx = tx
		if err := a.hooks.RunBeforeUserCreate(ctx, ev); err != nil {
			return err
		}
		if err := tx.Users().Create(ctx, user); err != nil {
			return err
		}
		return tx.Accounts().Create(ctx, account)
	})
	if err != nil {
		if isConflict(err) {
			return nil, apierr.ErrAccountAlreadyLinked
		}
		return nil, publicError(err)
	}
	ev.Tx = nil
	a.hooks.RunAfterUserCreate(ctx, ev)
	a.hooks.RunAfterAccountLink(ctx, &hook.AccountLink{User: user, Account: account})
	a.emitter.Emit(ctx, events.SignUp, user.ID, map[string]any{"provider": providerID})
	a.emitter.Emit(ctx, events.AccountLinked, user.ID, map[string]any{"provider": providerID})
	return user, nil
}

func (a *Auth) requireUser(w http.ResponseWriter, r *http.Request) (*store.User, bool) {
	_, user, err := a.resolveSession(r.Context(), r)
	if err != nil {
		a.writeError(w, err)
		return nil, false
	}
	if user == nil {
		a.writeError(w, apierr.ErrUnauthorized)
		return nil, false
	}
	return user, true
}

func (a *Auth) handleAccountProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	list, err := a.cfg.store.Accounts().ListByUser(ctx, user.ID)
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	entries := make([]providerEntry, 0, len(list))
	for _, acct := range list {
		entries = append(entries, providerEntry{
			Provider: acct.Provider, AccountID: acct.ProviderAccountID, LinkedAt: acct.CreatedAt,
		})
	}
	hasPassword := false
	if _, err := a.cfg.store.Users().GetCredential(ctx, user.ID); err == nil {
		hasPassword = true
	}
	a.writeJSON(w, http.StatusOK, providersResponse{Providers: entries, HasPassword: hasPassword})
}

func (a *Auth) handleAccountLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	user, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	p, err := a.provider(r.PathValue("provider"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	redirectTo := a.safeRedirect(r.URL.Query().Get("redirect_to"), a.cfg.baseURL)
	url, err := a.startOAuth(ctx, w, p, redirectTo, &user.ID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, linkResponse{URL: url})
}

func (a *Auth) handleAccountUnlink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	user, ok := a.requireUser(w, r)
	if !ok {
		return
	}
	providerID := r.PathValue("provider")
	if _, err := a.provider(providerID); err != nil {
		a.writeError(w, err)
		return
	}
	// The check and the delete run in one transaction. The transaction first
	// writes the user row, which takes an exclusive row lock, so two
	// concurrent unlink requests for one user cannot both believe that another
	// authentication method remains.
	err := a.cfg.store.Transaction(ctx, func(tx store.Store) error {
		locked, err := tx.Users().GetByID(ctx, user.ID)
		if err != nil {
			return err
		}
		locked.UpdatedAt = a.cfg.now()
		if err := tx.Users().Update(ctx, locked); err != nil {
			return err
		}
		list, err := tx.Accounts().ListByUser(ctx, user.ID)
		if err != nil {
			return err
		}
		found := false
		for _, acct := range list {
			if acct.Provider == providerID {
				found = true
				break
			}
		}
		if !found {
			return apierr.ErrAccountNotLinked
		}
		hasPassword := false
		if _, err := tx.Users().GetCredential(ctx, user.ID); err == nil {
			hasPassword = true
		}
		// A user must keep at least one usable authentication method.
		if !hasPassword && len(list)-1 == 0 {
			return apierr.ErrLastAuthMethod
		}
		return tx.Accounts().Delete(ctx, user.ID, providerID)
	})
	if err != nil {
		if isNotFound(err) {
			a.writeError(w, apierr.ErrAccountNotLinked)
			return
		}
		a.writeError(w, publicError(err))
		return
	}
	a.emitter.Emit(ctx, events.AccountUnlinked, user.ID, map[string]any{"provider": providerID})
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}
