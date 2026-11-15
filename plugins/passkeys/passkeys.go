// Package passkeys is the official WebAuthn passkey plugin of Auth-All.
//
// A signed-in user registers passkeys, lists them, and deletes them. Anyone
// signs in with a passkey through a discoverable ceremony, so the browser
// offers the passkeys it holds and no address is named. The plugin verifies
// every response with github.com/go-webauthn/webauthn.
//
// A sign-in with the user-verified flag issues the session at once, because
// the device proved two factors. A sign-in without the flag runs the TOTP
// challenge of a user with a confirmed second factor, as every other first
// factor does.
//
// The plugin owns two tables. Migrate creates them.
package passkeys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// ID is the plugin identifier. It is also the session method of a passkey
// sign-in.
const ID = "passkey"

// DefaultFreshAge is the default maximum age of a session that registers or
// deletes a passkey.
const DefaultFreshAge = 10 * time.Minute

// challengeTTL is the lifetime of one ceremony.
const challengeTTL = 5 * time.Minute

// cleanupWindow keeps an expired ceremony for one hour before Cleanup removes
// it, so a late finish still gets the uniform invalid response.
const cleanupWindow = time.Hour

// User verification requirements.
const (
	// VerificationRequired refuses an authenticator that cannot check a PIN
	// or a biometric.
	VerificationRequired = "required"
	// VerificationPreferred asks for a check and accepts an authenticator
	// without one. It is the default.
	VerificationPreferred = "preferred"
	// VerificationDiscouraged asks the authenticator to skip the check.
	VerificationDiscouraged = "discouraged"
)

// Plugin is the passkeys plugin.
type Plugin struct {
	rpID             string
	rpDisplayName    string
	origins          []string
	userVerification string
	freshAge         time.Duration

	svc        plugin.Services
	signIn     plugin.SignInService
	principals plugin.PrincipalService
	protect    func(next http.Handler) http.Handler
	rows       store.PasskeyStore
	web        *webauthn.WebAuthn
	now        func() time.Time
}

// Option configures the plugin.
type Option func(*Plugin)

// RPID sets the relying party ID, which is the registrable domain that every
// passkey binds to, for example "example.com". The default is the host of the
// base URL. A passkey of one RP ID never works under another, so the value must
// stay the same for the life of the application.
func RPID(id string) Option { return func(p *Plugin) { p.rpID = id } }

// RPDisplayName sets the name that the browser shows during a ceremony. The
// default is the RP ID.
func RPDisplayName(name string) Option { return func(p *Plugin) { p.rpDisplayName = name } }

// Origins sets the origins that a response may come from, for example
// "https://app.example.com". The default is the origin of the base URL.
func Origins(origins ...string) Option {
	return func(p *Plugin) { p.origins = append([]string(nil), origins...) }
}

// UserVerification sets the user verification requirement of both ceremonies:
// VerificationRequired, VerificationPreferred, or VerificationDiscouraged. The
// default is VerificationPreferred.
func UserVerification(v string) Option { return func(p *Plugin) { p.userVerification = v } }

// FreshAge sets the maximum age of a session that registers or deletes a
// passkey. An older session gets 403 SESSION_NOT_FRESH. The default is
// DefaultFreshAge.
func FreshAge(d time.Duration) Option { return func(p *Plugin) { p.freshAge = d } }

// New returns the passkeys plugin.
func New(opts ...Option) *Plugin {
	p := &Plugin{userVerification: VerificationPreferred, freshAge: DefaultFreshAge}
	for _, o := range opts {
		o(p)
	}
	return p
}

// ID implements plugin.Plugin.
func (p *Plugin) ID() string { return ID }

// Register implements plugin.Plugin.
func (p *Plugin) Register(r *plugin.Registry) error {
	switch p.userVerification {
	case VerificationRequired, VerificationPreferred, VerificationDiscouraged:
	default:
		return fmt.Errorf("authall/passkeys: the user verification %q is unknown", p.userVerification)
	}
	if p.freshAge <= 0 {
		return errors.New("authall/passkeys: the fresh age must be positive")
	}
	svc := r.Services()
	signIn, ok := svc.(plugin.SignInService)
	if !ok {
		return errors.New("authall/passkeys: this Auth-All version has no sign-in service")
	}
	principals, ok := svc.(plugin.PrincipalServices)
	if !ok {
		return errors.New("authall/passkeys: this Auth-All version has no principal service")
	}
	protector, ok := svc.(plugin.ProtectService)
	if !ok {
		return errors.New("authall/passkeys: this Auth-All version has no authentication middleware")
	}
	rows, ok := svc.Store().(store.PasskeyStore)
	if !ok {
		return errors.New("authall/passkeys: the configured store holds no passkey")
	}
	if err := p.resolveRelyingParty(svc); err != nil {
		return err
	}
	web, err := webauthn.New(&webauthn.Config{
		RPID:                  p.rpID,
		RPDisplayName:         p.rpDisplayName,
		RPOrigins:             p.origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.UserVerificationRequirement(p.userVerification),
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login:        webauthn.TimeoutConfig{Timeout: challengeTTL, TimeoutUVD: challengeTTL},
			Registration: webauthn.TimeoutConfig{Timeout: challengeTTL, TimeoutUVD: challengeTTL},
		},
	})
	if err != nil {
		return fmt.Errorf("authall/passkeys: %w", err)
	}
	p.svc = svc
	p.signIn = signIn
	p.principals = principals.Principals()
	p.protect = protector.Protect
	p.rows = rows
	p.web = web
	p.now = svc.Now

	options := schema.DefaultOptions()
	if reporter, ok := svc.(plugin.SchemaService); ok {
		options = reporter.SchemaOptions()
	}
	for _, t := range schema.PasskeyTables(options) {
		r.Schema(t)
	}
	units, err := schema.PasskeyUnits(options, ID)
	if err != nil {
		return err
	}
	for _, u := range units {
		r.Unit(u)
	}
	registerSchemas(r)
	p.registerRoutes(r)
	return nil
}

// resolveRelyingParty fills the RP ID, the display name, and the origins from
// the base URL when the host names none. A base URL that changes at run time
// cannot bind a passkey, so the host must name both values then.
func (p *Plugin) resolveRelyingParty(svc plugin.Services) error {
	fixed := true
	if rt, ok := svc.(plugin.RuntimeService); ok {
		fixed = rt.BaseURLFixed()
	}
	if p.rpID == "" || len(p.origins) == 0 {
		if !fixed {
			return errors.New("authall/passkeys: a base URL source changes at run time, so passkeys.RPID " +
				"and passkeys.Origins are required")
		}
		base, err := url.Parse(svc.BaseURL())
		if err != nil || base.Hostname() == "" {
			return errors.New("authall/passkeys: the base URL names no host, so passkeys.RPID and " +
				"passkeys.Origins are required")
		}
		if p.rpID == "" {
			p.rpID = base.Hostname()
		}
		if len(p.origins) == 0 {
			p.origins = []string{base.Scheme + "://" + base.Host}
		}
	}
	if p.rpDisplayName == "" {
		p.rpDisplayName = p.rpID
	}
	return nil
}

// Cleanup removes the ceremonies that expired more than one hour ago. The
// host calls it on its own schedule, because Auth-All runs no background work.
func (p *Plugin) Cleanup(ctx context.Context) (int, error) {
	return p.rows.DeleteExpiredPasskeyChallenges(ctx, p.now().Add(-cleanupWindow))
}

// List returns every passkey of one user, and the newest comes first.
func (p *Plugin) List(ctx context.Context, userID string) ([]store.Passkey, error) {
	keys, err := p.rows.ListPasskeys(ctx, userID)
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	return keys, nil
}

// Delete removes one passkey of one user. It returns NOT_FOUND when the user
// holds no passkey with that identifier.
func (p *Plugin) Delete(ctx context.Context, userID, passkeyID string) error {
	if err := p.rows.DeletePasskey(ctx, passkeyID, userID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return apierr.ErrNotFound
		}
		return apierr.ErrInternal.WithCause(err)
	}
	p.svc.Events().Emit(ctx, events.PasskeyDeleted, userID, map[string]any{"passkey_id": passkeyID})
	return nil
}

// fresh refuses a session that is older than the fresh age.
func (p *Plugin) fresh(sess *store.Session) error {
	if sess == nil || p.now().Sub(sess.CreatedAt) > p.freshAge {
		return apierr.ErrSessionNotFresh
	}
	return nil
}

// beginRegistration starts the registration ceremony of one user. It returns
// the ceremony handle and the creation options for the browser.
func (p *Plugin) beginRegistration(ctx context.Context, user *store.User) (string, *protocol.CredentialCreation, error) {
	existing, err := p.rows.ListPasskeys(ctx, user.ID)
	if err != nil {
		return "", nil, apierr.ErrInternal.WithCause(err)
	}
	account, err := newAccount(user, existing)
	if err != nil {
		return "", nil, apierr.ErrInternal.WithCause(err)
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(account.credentials))
	for i := range account.credentials {
		exclude = append(exclude, account.credentials[i].Descriptor())
	}
	creation, session, err := p.web.BeginRegistration(account, webauthn.WithExclusions(exclude))
	if err != nil {
		return "", nil, apierr.ErrInternal.WithCause(err)
	}
	userID := user.ID
	handle, err := p.saveCeremony(ctx, store.PasskeyChallengeRegistration, &userID, session)
	if err != nil {
		return "", nil, err
	}
	return handle, creation, nil
}

// finishRegistration verifies the attestation of one ceremony and stores the
// passkey.
func (p *Plugin) finishRegistration(ctx context.Context, user *store.User, handle, name string,
	response json.RawMessage) (*store.Passkey, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 100 {
		return nil, apierr.ErrInvalidRequest.WithMessage("The name must have 1 to 100 characters.")
	}
	ceremony, session, err := p.consumeCeremony(ctx, store.PasskeyChallengeRegistration, handle)
	if err != nil {
		return nil, err
	}
	if ceremony.UserID == nil || *ceremony.UserID != user.ID {
		return nil, apierr.ErrPasskeyInvalid
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, apierr.ErrPasskeyInvalid.WithCause(err)
	}
	existing, err := p.rows.ListPasskeys(ctx, user.ID)
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	account, err := newAccount(user, existing)
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	credential, err := p.web.CreateCredential(account, *session, parsed)
	if err != nil {
		return nil, apierr.ErrPasskeyInvalid.WithCause(err)
	}
	record, err := json.Marshal(credential)
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	key := &store.Passkey{
		ID:           uuid.NewString(),
		UserID:       user.ID,
		CredentialID: base64.RawURLEncoding.EncodeToString(credential.ID),
		Name:         name,
		Credential:   string(record),
		CreatedAt:    p.now(),
	}
	if err := p.rows.CreatePasskey(ctx, key); err != nil {
		if errors.Is(err, store.ErrConflict) {
			// An authenticator never reuses a credential ID, so a repeated
			// ID is a replayed or forged response.
			return nil, apierr.ErrPasskeyInvalid.WithCause(err)
		}
		return nil, apierr.ErrInternal.WithCause(err)
	}
	p.svc.Events().Emit(ctx, events.PasskeyRegistered, user.ID, map[string]any{"passkey_id": key.ID})
	return key, nil
}

// beginSignIn starts a discoverable sign-in ceremony.
func (p *Plugin) beginSignIn(ctx context.Context) (string, *protocol.CredentialAssertion, error) {
	assertion, session, err := p.web.BeginDiscoverableLogin()
	if err != nil {
		return "", nil, apierr.ErrInternal.WithCause(err)
	}
	handle, err := p.saveCeremony(ctx, store.PasskeyChallengeSignIn, nil, session)
	if err != nil {
		return "", nil, err
	}
	return handle, assertion, nil
}

// signInResult is the outcome of a verified assertion.
type signInResult struct {
	user *store.User
	// verified reports the user-verified flag of the assertion.
	verified bool
}

// finishSignIn verifies the assertion of one ceremony and returns the user. It
// writes the new sign count and flags of the passkey.
func (p *Plugin) finishSignIn(ctx context.Context, handle string, response json.RawMessage) (*signInResult, error) {
	_, session, err := p.consumeCeremony(ctx, store.PasskeyChallengeSignIn, handle)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, apierr.ErrPasskeyInvalid.WithCause(err)
	}
	var (
		key  *store.Passkey
		user *store.User
	)
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		found, err := p.rows.PasskeyByCredentialID(ctx, base64.RawURLEncoding.EncodeToString(rawID))
		if err != nil {
			return nil, err
		}
		// The user handle is the user ID that registration wrote, so a handle
		// of another user names no passkey of this one.
		if string(userHandle) != found.UserID {
			return nil, errors.New("the user handle names another user")
		}
		owner, err := p.svc.Users().ByID(ctx, found.UserID)
		if err != nil {
			return nil, err
		}
		account, err := newAccount(owner, []store.Passkey{*found})
		if err != nil {
			return nil, err
		}
		key, user = found, owner
		return account, nil
	}
	_, credential, err := p.web.ValidatePasskeyLogin(lookup, *session, parsed)
	if err != nil {
		return nil, apierr.ErrPasskeyInvalid.WithCause(err)
	}
	if credential.Authenticator.CloneWarning {
		// The counter did not grow, so a second copy of the private key can
		// exist. The stored record stays as it is.
		p.svc.Events().Emit(ctx, events.PasskeyCloneDetected, user.ID, map[string]any{"passkey_id": key.ID})
		return nil, apierr.ErrPasskeyInvalid
	}
	record, err := json.Marshal(credential)
	if err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	if err := p.rows.UpdatePasskeyUse(ctx, key.ID, string(record), p.now()); err != nil {
		return nil, apierr.ErrInternal.WithCause(err)
	}
	return &signInResult{user: user, verified: parsed.Response.AuthenticatorData.Flags.HasUserVerified()}, nil
}

// saveCeremony writes the state of one ceremony and returns the plaintext
// handle. The row holds the digest only.
func (p *Plugin) saveCeremony(ctx context.Context, kind string, userID *string, session *webauthn.SessionData) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", apierr.ErrInternal.WithCause(err)
	}
	handle, err := crypto.NewToken()
	if err != nil {
		return "", apierr.ErrInternal.WithCause(err)
	}
	now := p.now()
	if err := p.rows.CreatePasskeyChallenge(ctx, &store.PasskeyChallenge{
		ID: crypto.HashToken(handle), Kind: kind, UserID: userID, SessionData: string(data),
		CreatedAt: now, ExpiresAt: now.Add(challengeTTL),
	}); err != nil {
		return "", apierr.ErrInternal.WithCause(err)
	}
	return handle, nil
}

// consumeCeremony consumes one ceremony and decodes its state into a new
// value, so no field of an earlier ceremony carries over.
func (p *Plugin) consumeCeremony(ctx context.Context, kind, handle string) (*store.PasskeyChallenge, *webauthn.SessionData, error) {
	if handle == "" {
		return nil, nil, apierr.ErrPasskeyInvalid
	}
	ceremony, err := p.rows.ConsumePasskeyChallenge(ctx, crypto.HashToken(handle), kind, p.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, apierr.ErrPasskeyInvalid
		}
		return nil, nil, apierr.ErrInternal.WithCause(err)
	}
	session := new(webauthn.SessionData)
	if err := json.Unmarshal([]byte(ceremony.SessionData), session); err != nil {
		return nil, nil, apierr.ErrInternal.WithCause(err)
	}
	return ceremony, session, nil
}

// account adapts one user and its passkeys to the webauthn.User interface.
type account struct {
	user        *store.User
	credentials []webauthn.Credential
}

// newAccount decodes the credential records of the passkeys.
func newAccount(user *store.User, keys []store.Passkey) (*account, error) {
	out := &account{user: user, credentials: make([]webauthn.Credential, 0, len(keys))}
	for _, key := range keys {
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(key.Credential), &c); err != nil {
			return nil, fmt.Errorf("decode the passkey %s: %w", key.ID, err)
		}
		out.credentials = append(out.credentials, c)
	}
	return out, nil
}

// WebAuthnID returns the user handle. It is the user ID, so the sign-in finds
// the owner without a lookup table.
func (a *account) WebAuthnID() []byte { return []byte(a.user.ID) }

// WebAuthnName returns the address of the user.
func (a *account) WebAuthnName() string { return a.user.Email }

// WebAuthnDisplayName returns the display name, or the address when the user
// has none.
func (a *account) WebAuthnDisplayName() string {
	if a.user.DisplayName != "" {
		return a.user.DisplayName
	}
	return a.user.Email
}

// WebAuthnCredentials returns the decoded passkeys.
func (a *account) WebAuthnCredentials() []webauthn.Credential { return a.credentials }
