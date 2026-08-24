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

// writeError writes the public error envelope and logs the private cause.
func (a *Auth) writeError(w http.ResponseWriter, err error) {
	e := apierr.From(err)
	if cause := e.Unwrap(); cause != nil {
		a.cfg.logger.Error("authall: request failed", "code", string(e.Code), "error", cause.Error())
	}
	apierr.Write(w, e)
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
		return nil
	}
	if a.originAllowed(r, origin) {
		return nil
	}
	return apierr.ErrOriginNotAllowed
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
//
// A browser resolves a backslash like a forward slash and drops a control
// character, so "/\\evil.example.com" would reach another origin. Auth-All
// therefore rejects a candidate that carries a backslash or a control
// character, and it rejects every scheme-relative reference.
func (a *Auth) safeRedirect(candidate, fallback string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return fallback
	}
	if strings.ContainsRune(candidate, '\\') || hasControlRune(candidate) {
		return fallback
	}
	if strings.HasPrefix(candidate, "/") {
		if strings.HasPrefix(candidate, "//") {
			return fallback
		}
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
	origin := u.Scheme + "://" + u.Host
	for _, allowed := range a.trustedOrigins {
		if strings.EqualFold(allowed, origin) {
			return candidate
		}
	}
	return fallback
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
