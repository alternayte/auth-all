package authall

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/alternayte/auth-all/apierr"
)

// maxBodyBytes bounds a JSON request body.
const maxBodyBytes = 1 << 20

// writeJSON writes a JSON response.
func (a *Auth) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		a.cfg.logger.Error("authall: cannot write the response", "error", err.Error())
	}
}

// writeError writes the public error envelope and logs the private cause. A
// host writer replaces the envelope, and it never receives the private cause.
func (a *Auth) writeError(w http.ResponseWriter, r *http.Request, err error) {
	e := apierr.From(err)
	if cause := e.Unwrap(); cause != nil {
		a.cfg.logger.Error("authall: request failed", "code", string(e.Code), "error", cause.Error())
	}
	if a.cfg.errorWriter == nil {
		apierr.Write(w, e)
		return
	}
	// The public error carries no cause, so the host cannot leak it.
	public := apierr.New(e.Code, e.Status, e.Message)
	a.cfg.errorWriter(w, r, public)
}

// decodeJSON reads a bounded JSON request body.
func (a *Auth) decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return apierr.ErrInvalidRequest
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return apierr.ErrInvalidRequest.WithCause(err)
	}
	return nil
}

// checkOrigin rejects a state-changing request from an untrusted browser
// origin. A request without an Origin or Referer header comes from a client
// that is not a browser and passes.
//
// WithStrictOriginCheck changes that last rule for a request that carries the
// session cookie. See strictOriginOK.
func (a *Auth) checkOrigin(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" || origin == "null" {
		if ref := r.Header.Get("Referer"); ref != "" {
			u, err := url.Parse(ref)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return apierr.ErrOriginNotAllowed
			}
			origin = u.Scheme + "://" + u.Host
		}
	}
	if origin == "" {
		// The request names no origin that Auth-All can judge. A client that
		// is not a browser sends none, and it carries no ambient credential.
		if a.cfg.strictOriginCheck && a.hasSessionCookie(r) && !strictOriginOK(r) {
			return apierr.ErrOriginNotAllowed
		}
		return nil
	}
	if a.originAllowed(r, origin) {
		return nil
	}
	return apierr.ErrOriginNotAllowed
}

// hasSessionCookie reports whether the request carries the session cookie. An
// ambient credential is the one that a cross-site page can use.
func (a *Auth) hasSessionCookie(r *http.Request) bool {
	c, err := r.Cookie(a.cfg.cookie.Name)
	return err == nil && c.Value != ""
}

// strictOriginOK reports whether the fetch metadata of a request names a site
// that Auth-All accepts. It runs only in strict mode, and only for an unsafe
// request that names no origin.
//
// A browser that sends no Origin still sends Sec-Fetch-Site, so a request with
// neither header is refused. An opaque origin reaches this point as well,
// because "null" is never a trusted origin.
//
// Only "same-origin" passes. A same-site request comes from another origin of
// the registrable domain, so it needs an Origin header that the trusted list
// holds. The cross-site protection of the standard library applies the same
// rule to a host route.
func strictOriginOK(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "same-origin")
}

func (a *Auth) originAllowed(r *http.Request, origin string) bool {
	origin = strings.TrimSuffix(origin, "/")
	for _, allowed := range a.trustedOrigins {
		if strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return strings.EqualFold(requestOrigin(r), origin)
}

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host
}

// safeRedirect returns candidate when it is a relative path of this
// application or points at a trusted origin, and fallback otherwise.
func (a *Auth) safeRedirect(candidate, fallback string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return fallback
	}
	if unsafeReference(candidate) {
		return fallback
	}
	if strings.HasPrefix(candidate, "/") {
		u, err := url.Parse(candidate)
		if err != nil || u.Scheme != "" || u.Host != "" {
			return fallback
		}
		return candidate
	}
	u, err := url.Parse(candidate)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fallback
	}
	// User information hides the true host from a person who reads the link,
	// so a target that carries it is never safe.
	if u.User != nil {
		return fallback
	}
	origin := u.Scheme + "://" + u.Host
	for _, allowed := range a.trustedOrigins {
		if strings.EqualFold(allowed, origin) {
			return candidate
		}
	}
	return fallback
}

// unsafeReference reports whether a redirect candidate can reach another
// origin.
//
// A browser resolves a backslash like a forward slash and drops a control
// character, so "/\\evil.example.com" and "/\t/evil.example.com" would reach
// another origin. A proxy or a framework can also decode a percent escape
// before another parser reads the value, so "/%09/evil.example.com" can become
// "//evil.example.com". The function therefore checks the literal form and the
// decoded form of the candidate.
//
// A candidate with an invalid percent escape is unsafe, because two parsers
// can repair it in two ways.
func unsafeReference(candidate string) bool {
	forms := []string{candidate}
	decoded, err := url.PathUnescape(candidate)
	if err != nil {
		return true
	}
	if decoded != candidate {
		forms = append(forms, decoded)
	}
	for _, form := range forms {
		if strings.ContainsRune(form, '\\') || hasControlRune(form) {
			return true
		}
		// A scheme-relative reference names another origin.
		if strings.HasPrefix(form, "//") {
			return true
		}
	}
	return false
}

// hasControlRune reports whether s carries a character that a browser drops
// while it parses a URL.
func hasControlRune(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// parseProxyBlock reads one trusted proxy value. It accepts a CIDR block and a
// single IP address. A single address becomes a block of one host.
func parseProxyBlock(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if block, err := netip.ParsePrefix(raw); err == nil {
		return block.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// trustedProxy reports whether a declared block contains the address.
func (a *Auth) trustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, block := range a.cfg.proxyNets {
		if block.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteHost returns the address of the direct peer of a request.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientIP returns the request IP for a rate-limit key.
//
// Any client can set X-Forwarded-For, so a key that trusts the header is
// forgeable, and the brute-force defense fails. Auth-All therefore reads the
// header only when a declared trusted proxy holds the direct peer.
//
// The walk goes from right to left, because a proxy appends the address it
// saw. Auth-All returns the first address that no trusted block contains, so a
// hop that the client prepends never wins. Auth-All returns the address of the
// direct peer when every hop is trusted, and also when a hop is malformed. A
// malformed hop hides every address to its left, so nothing to its left is
// trustworthy.
func (a *Auth) clientIP(r *http.Request) string {
	peer := remoteHost(r)
	if len(a.cfg.proxyNets) == 0 {
		return peer
	}
	addr, err := netip.ParseAddr(peer)
	if err != nil || !a.trustedProxy(addr) {
		return peer
	}
	var hops []string
	for _, value := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(value, ",") {
			hops = append(hops, strings.TrimSpace(part))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(hops[i])
		if err != nil {
			return peer
		}
		if !a.trustedProxy(hop) {
			return hop.Unmap().String()
		}
	}
	return peer
}
