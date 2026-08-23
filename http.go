package authall

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
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

// clientIP returns the request IP for a rate-limit key.
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
