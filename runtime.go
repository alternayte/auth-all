package authall

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/alternayte/auth-all/email"
	"github.com/alternayte/auth-all/oauth"
)

// The values of this file can come from a host source, which WithBaseURLSource,
// WithEmailSenderSource, and WithProviderSource set. Each use reads the source
// again, so a change in the host applies to the next request on every
// instance.

// normalizeBaseURL trims a base URL and proves that it is absolute. An empty
// value means that no base URL is configured.
func normalizeBaseURL(raw string) (string, error) {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		return "", nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("authall: the base URL must be absolute, for example https://app.example.com")
	}
	return base, nil
}

// baseURLFor returns the base URL for one use.
func (a *Auth) baseURLFor(ctx context.Context) (string, error) {
	if a.cfg.baseURLSource == nil {
		return a.cfg.baseURL, nil
	}
	raw, err := a.cfg.baseURLSource(ctx)
	if err != nil {
		return "", fmt.Errorf("authall: the base URL source failed: %w", err)
	}
	base, err := normalizeBaseURL(raw)
	if err != nil {
		return "", fmt.Errorf("authall: the base URL source returned %q: %w", raw, err)
	}
	return base, nil
}

// senderFor returns the email sender for one message. A nil sender with a nil
// error means that no sender is configured.
func (a *Auth) senderFor(ctx context.Context) (email.Sender, error) {
	if a.cfg.senderSource == nil {
		return a.cfg.sender, nil
	}
	s, err := a.cfg.senderSource(ctx)
	if err != nil {
		return nil, fmt.Errorf("authall: the email sender source failed: %w", err)
	}
	return s, nil
}

// legacySender serves plugin.Services.Email, which carries no context and no
// error. A source error becomes no sender, and the log holds the error.
func (a *Auth) legacySender() email.Sender {
	s, err := a.senderFor(context.Background())
	if err != nil {
		a.cfg.logger.Error("authall: a plugin cannot read the email sender", "error", err.Error())
		return nil
	}
	return s
}

// legacyBaseURL serves plugin.Services.BaseURL, which carries no context and
// no error. A source error becomes an empty value, and the log holds the
// error.
func (a *Auth) legacyBaseURL() string {
	base, err := a.baseURLFor(context.Background())
	if err != nil {
		a.cfg.logger.Error("authall: a plugin cannot read the base URL", "error", err.Error())
		return ""
	}
	return base
}

// requireSender returns the sender of a flow that cannot run without one. It
// logs the reason, because the public error carries none.
func (a *Auth) requireSender(ctx context.Context, flow string) (email.Sender, bool) {
	s, err := a.senderFor(ctx)
	if err != nil {
		a.cfg.logger.Error("authall: "+flow+" needs an email sender", "error", err.Error())
		return nil, false
	}
	if s == nil {
		a.cfg.logger.Error("authall: " + flow + " needs an email sender")
		return nil, false
	}
	return s, true
}

// hasProviders reports whether the OAuth routes can serve a provider.
func (a *Auth) hasProviders() bool {
	return len(a.providers) > 0 || len(a.cfg.providerSources) > 0
}

// providersFor returns the configured providers by id for one request. The
// static providers passed their checks in New.
func (a *Auth) providersFor(ctx context.Context) (map[string]oauth.Provider, error) {
	if len(a.cfg.providerSources) == 0 {
		return a.providers, nil
	}
	out := make(map[string]oauth.Provider, len(a.providers))
	for id, p := range a.providers {
		out[id] = p
	}
	for _, src := range a.cfg.providerSources {
		list, err := src(ctx)
		if err != nil {
			return nil, fmt.Errorf("authall: the OAuth provider source failed: %w", err)
		}
		for _, p := range list {
			if p == nil {
				return nil, fmt.Errorf("authall: the OAuth provider source returned a nil provider")
			}
			id := p.ID()
			if id == "" {
				return nil, fmt.Errorf("authall: an OAuth provider has an empty id")
			}
			if _, exists := out[id]; exists {
				return nil, fmt.Errorf("authall: the OAuth provider %q is registered twice", id)
			}
			out[id] = p
		}
	}
	return out, nil
}

// ProviderIDs returns the ids of the OAuth providers that serve now, sorted. It
// reads every provider source, so a sign-in page that calls it shows the
// current set.
func (a *Auth) ProviderIDs(ctx context.Context) ([]string, error) {
	set, err := a.providersFor(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// originsFor returns the trusted origins for one request: the origin of the
// base URL and every origin of WithTrustedOrigins.
func (a *Auth) originsFor(ctx context.Context) ([]string, error) {
	if a.cfg.baseURLSource == nil {
		return a.trustedOrigins, nil
	}
	base, err := a.baseURLFor(ctx)
	if err != nil {
		return nil, err
	}
	return originList(base, a.cfg.trustedOrigins), nil
}

// originProtection is one cross-origin check and the origin list it trusts.
type originProtection struct {
	key        string
	protection *http.CrossOriginProtection
}

// hostProtection returns the cross-origin check of a host route. With a base
// URL source the trusted list can change, so the check is built again when
// the list differs from the last one.
func (a *Auth) hostProtection(ctx context.Context) (*http.CrossOriginProtection, error) {
	if a.cfg.baseURLSource == nil {
		return a.crossOrigin, nil
	}
	origins, err := a.originsFor(ctx)
	if err != nil {
		return nil, err
	}
	key := strings.Join(origins, " ")
	if last := a.dynamicOrigin.Load(); last != nil && last.key == key {
		return last.protection, nil
	}
	protection, err := newProtection(origins)
	if err != nil {
		return nil, err
	}
	a.dynamicOrigin.Store(&originProtection{key: key, protection: protection})
	return protection, nil
}

// newProtection builds the standard cross-origin check over a trusted list.
func newProtection(origins []string) (*http.CrossOriginProtection, error) {
	protection := http.NewCrossOriginProtection()
	for _, origin := range origins {
		if err := protection.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("authall: the trusted origin %q is not usable for the origin check: %w",
				origin, err)
		}
	}
	return protection, nil
}
