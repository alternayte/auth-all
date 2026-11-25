package oauthprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// Limits of Client ID Metadata Documents.
const (
	// DefaultCIMDMaxBytes bounds the size of one metadata document.
	DefaultCIMDMaxBytes = 5 << 10
	// DefaultCIMDTimeout bounds one fetch of a metadata document.
	DefaultCIMDTimeout = 5 * time.Second
	// DefaultCIMDCacheTTL is the default ceiling of the document cache.
	DefaultCIMDCacheTTL = 24 * time.Hour
	// MinCIMDCacheTTL is the floor of the document cache. A document that asks
	// for a shorter lifetime stays this long, so a client cannot make the
	// server fetch on every request.
	MinCIMDCacheTTL = 5 * time.Minute
)

// cimdCacheEntries bounds the number of cached documents. A client identifier
// is chosen by an unknown party, so the cache must not grow without a bound.
const cimdCacheEntries = 1024

// cimdMaxClientIDLength bounds the length of a client identifier URL.
const cimdMaxClientIDLength = 2048

// cimdMaxNameLength bounds the client name that the consent page shows.
const cimdMaxNameLength = 200

// CIMDOptions configures the Client ID Metadata Documents of an MCP client.
// A zero field takes its default.
type CIMDOptions struct {
	// MaxBytes bounds the size of one document. The default is
	// DefaultCIMDMaxBytes.
	MaxBytes int64
	// Timeout bounds one fetch, from the connection to the last byte. The
	// default is DefaultCIMDTimeout.
	Timeout time.Duration
	// CacheTTL is the ceiling of the cache. A document stays cached for the
	// lifetime its Cache-Control or Expires header names, at least
	// MinCIMDCacheTTL and at most CacheTTL. A failed fetch of a cached
	// document uses the cached copy until CacheTTL after its last successful
	// fetch. The default is DefaultCIMDCacheTTL.
	CacheTTL time.Duration
}

// AllowClientIDMetadataDocuments accepts a client whose client_id is the HTTPS
// URL of its metadata document, as the MCP authorization specification
// prefers. Such a client needs no registration. The authorize route fetches
// the document from the network, with no redirect, no private, loopback or
// link-local address, and the size and time limits of the options.
func AllowClientIDMetadataDocuments(o CIMDOptions) Option {
	return func(p *Plugin) {
		opts := o
		p.cimdOptions = &opts
	}
}

// cimdError is a metadata document that the server refuses. Its message is
// safe to show to the client.
type cimdError struct{ msg string }

func (e *cimdError) Error() string { return e.msg }

func refuseCIMD(format string, args ...any) error {
	return &cimdError{msg: fmt.Sprintf(format, args...)}
}

// errBlockedAddress reports a fetch whose address is not public.
var errBlockedAddress = errors.New("the address is not public")

// isCIMDClientID reports whether a client identifier has the form of a URL. A
// plain http URL also takes the metadata document path, so it fails with a
// clear reason and not as an unknown client.
func isCIMDClientID(id string) bool {
	lower := strings.ToLower(id)
	return strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://")
}

// checkCIMDClientID validates the form of a client identifier URL before any
// network call.
func checkCIMDClientID(id string) (*url.URL, error) {
	if len(id) > cimdMaxClientIDLength {
		return nil, refuseCIMD("the client identifier URL is longer than %d bytes", cimdMaxClientIDLength)
	}
	u, err := url.Parse(id)
	if err != nil {
		return nil, refuseCIMD("the client identifier is no URL")
	}
	if u.Scheme != "https" {
		return nil, refuseCIMD("the client identifier URL must use https")
	}
	if u.Hostname() == "" {
		return nil, refuseCIMD("the client identifier URL names no host")
	}
	if u.User != nil {
		return nil, refuseCIMD("the client identifier URL carries user information")
	}
	if u.Fragment != "" || strings.Contains(id, "#") {
		return nil, refuseCIMD("the client identifier URL carries a fragment")
	}
	if len(u.Path) < 2 {
		return nil, refuseCIMD("the client identifier URL names no path")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, refuseCIMD("the client identifier URL carries a dot segment")
		}
	}
	return u, nil
}

// publicAddress reports whether the server may connect to an address. Every
// loopback, private, link-local, shared, reserved, and documentation range is
// refused, and so is a translation prefix that can embed one of them.
func publicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// blockedPrefixes are the special-purpose ranges that the standard library
// predicates do not name.
var blockedPrefixes = func() []netip.Prefix {
	ranges := []string{
		"0.0.0.0/8",       // this network
		"100.64.0.0/10",   // shared address space
		"192.0.0.0/24",    // protocol assignments
		"192.0.2.0/24",    // documentation
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"240.0.0.0/4",     // reserved, and the limited broadcast address
		"64:ff9b::/96",    // NAT64, which can embed a private IPv4 address
		"64:ff9b:1::/48",  // local NAT64
		"100::/64",        // discard
		"2001::/32",       // Teredo, which embeds an IPv4 address
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4, which embeds an IPv4 address
		"fec0::/10",       // site-local
	}
	out := make([]netip.Prefix, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, netip.MustParsePrefix(r))
	}
	return out
}()

// cimdDocument is the client metadata that a document carries. The fields
// follow RFC 7591.
type cimdDocument struct {
	ClientID                string          `json:"client_id"`
	ClientName              string          `json:"client_name"`
	LogoURI                 string          `json:"logo_uri"`
	RedirectURIs            []string        `json:"redirect_uris"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	Scope                   string          `json:"scope"`
	ClientSecret            json.RawMessage `json:"client_secret"`
	ClientSecretExpiresAt   json.RawMessage `json:"client_secret_expires_at"`
}

// cimdEntry is one cached document.
type cimdEntry struct {
	client       client
	etag         string
	lastModified string
	// freshUntil ends the lifetime the response headers allow.
	freshUntil time.Time
	// validated is the time of the last successful fetch or revalidation.
	validated time.Time
}

// cimdFetcher fetches, validates, and caches metadata documents.
type cimdFetcher struct {
	p        *Plugin
	maxBytes int64
	timeout  time.Duration
	ceiling  time.Duration
	http     *http.Client

	mu      sync.Mutex
	entries map[string]*cimdEntry
}

// newCIMDFetcher returns the fetcher of the options. permit decides which
// address the dialer may reach, and roots replaces the system certificate
// pool when it is not nil.
func newCIMDFetcher(p *Plugin, o CIMDOptions, permit func(netip.Addr) bool,
	roots *x509.CertPool) (*cimdFetcher, error) {
	if o.MaxBytes < 0 || o.Timeout < 0 || o.CacheTTL < 0 {
		return nil, errors.New("authall/oauthprovider: a metadata document limit is negative")
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = DefaultCIMDMaxBytes
	}
	if o.Timeout == 0 {
		o.Timeout = DefaultCIMDTimeout
	}
	if o.CacheTTL == 0 {
		o.CacheTTL = DefaultCIMDCacheTTL
	}
	if o.CacheTTL < MinCIMDCacheTTL {
		return nil, fmt.Errorf("authall/oauthprovider: the metadata document cache ceiling is below %s",
			MinCIMDCacheTTL)
	}
	if permit == nil {
		permit = publicAddress
	}
	dialer := &net.Dialer{
		Timeout: o.Timeout,
		// Control runs after the name resolution, on the address the socket
		// connects to. A name that resolves to a private address, or that
		// changes its answer between two lookups, therefore reaches nothing.
		Control: func(network, address string, _ syscall.RawConn) error {
			if network != "tcp4" && network != "tcp6" {
				return errBlockedAddress
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return errBlockedAddress
			}
			addr, err := netip.ParseAddr(host)
			if err != nil || !permit(addr) {
				return errBlockedAddress
			}
			return nil
		},
	}
	transport := &http.Transport{
		// An environment proxy would connect on behalf of the server and
		// skip the address check, so the fetch uses none.
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    o.Timeout,
		ResponseHeaderTimeout:  o.Timeout,
		MaxResponseHeaderBytes: 16 << 10,
		MaxIdleConns:           16,
		IdleConnTimeout:        90 * time.Second,
		ForceAttemptHTTP2:      true,
	}
	return &cimdFetcher{
		p:        p,
		maxBytes: o.MaxBytes,
		timeout:  o.Timeout,
		ceiling:  o.CacheTTL,
		http: &http.Client{
			Transport: transport,
			Timeout:   o.Timeout,
			// A redirect answers as itself, and the status check refuses it.
			// A followed redirect could lead the fetch to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		entries: map[string]*cimdEntry{},
	}, nil
}

// cached returns the cached client of an identifier without a network call.
func (f *cimdFetcher) cached(id string) (client, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.entries[id]
	if !ok {
		return client{}, false
	}
	return e.client, true
}

// client returns the client of a metadata document URL.
func (f *cimdFetcher) client(ctx context.Context, id string) (client, error) {
	if _, err := checkCIMDClientID(id); err != nil {
		return client{}, err
	}
	now := f.p.now()
	f.mu.Lock()
	entry := f.entries[id]
	var prior cimdEntry
	if entry != nil {
		prior = *entry
	}
	f.mu.Unlock()
	if entry != nil && now.Before(prior.freshUntil) {
		return prior.client, nil
	}
	var stale *cimdEntry
	if entry != nil {
		stale = &prior
	}
	resp, body, err := f.fetch(ctx, id, stale)
	if err != nil {
		var refused *cimdError
		if errors.As(err, &refused) {
			f.drop(id)
			return client{}, err
		}
		return f.fallback(id, stale, now, err)
	}
	switch {
	case resp.StatusCode == http.StatusNotModified && stale != nil:
		next := *stale
		next.freshUntil = f.freshUntil(resp.Header, now)
		next.validated = now
		if etag := resp.Header.Get("ETag"); etag != "" {
			next.etag = etag
		}
		if modified := resp.Header.Get("Last-Modified"); modified != "" {
			next.lastModified = modified
		}
		f.store(id, &next, now)
		return next.client, nil
	case resp.StatusCode >= http.StatusInternalServerError || resp.StatusCode == http.StatusTooManyRequests:
		return f.fallback(id, stale, now, fmt.Errorf("status %d", resp.StatusCode))
	case resp.StatusCode != http.StatusOK:
		// The owner of the URL answered, and the answer is no document.
		f.drop(id)
		return client{}, refuseCIMD("the metadata document answered with status %d", resp.StatusCode)
	}
	c, err := f.p.cimdClient(id, body)
	if err != nil {
		f.drop(id)
		return client{}, err
	}
	next := &cimdEntry{
		client:       c,
		etag:         resp.Header.Get("ETag"),
		lastModified: resp.Header.Get("Last-Modified"),
		freshUntil:   f.freshUntil(resp.Header, now),
		validated:    now,
	}
	f.store(id, next, now)
	return c, nil
}

// fallback answers a failed fetch. A cached copy serves until the ceiling
// after its last successful fetch, and it is not fetched again for the floor,
// so an outage of the client host costs one fetch per floor.
func (f *cimdFetcher) fallback(id string, stale *cimdEntry, now time.Time, cause error) (client, error) {
	if stale != nil && now.Before(stale.validated.Add(f.ceiling)) {
		next := *stale
		next.freshUntil = now.Add(MinCIMDCacheTTL)
		if limit := stale.validated.Add(f.ceiling); next.freshUntil.After(limit) {
			next.freshUntil = limit
		}
		f.store(id, &next, now)
		return stale.client, nil
	}
	f.drop(id)
	reason := "the metadata document could not be fetched"
	if errors.Is(cause, errBlockedAddress) {
		reason = "the metadata document host resolves to an address that is not public"
	}
	return client{}, &cimdError{msg: reason}
}

// fetch runs one GET of a document. A refusal that no retry can change, such as
// an oversized body, returns a cimdError. Any other error is a failure of the
// network.
func (f *cimdFetcher) fetch(ctx context.Context, id string, stale *cimdEntry) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return nil, nil, refuseCIMD("the client identifier is no URL")
	}
	req.Header.Set("Accept", "application/json")
	if stale != nil {
		if stale.etag != "" {
			req.Header.Set("If-None-Match", stale.etag)
		}
		if stale.lastModified != "" {
			req.Header.Set("If-Modified-Since", stale.lastModified)
		}
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp, nil, nil
	}
	if resp.ContentLength > f.maxBytes {
		return nil, nil, refuseCIMD("the metadata document is larger than %d bytes", f.maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > f.maxBytes {
		return nil, nil, refuseCIMD("the metadata document is larger than %d bytes", f.maxBytes)
	}
	return resp, body, nil
}

// freshUntil returns the end of the lifetime the response headers allow,
// clamped to the floor and the ceiling. A response that forbids caching stays
// for the floor, because the floor bounds how often a client makes the server
// fetch.
func (f *cimdFetcher) freshUntil(h http.Header, now time.Time) time.Time {
	lifetime := cacheLifetime(h, now)
	if lifetime < MinCIMDCacheTTL {
		lifetime = MinCIMDCacheTTL
	}
	if lifetime > f.ceiling {
		lifetime = f.ceiling
	}
	return now.Add(lifetime)
}

// store writes one entry and keeps the cache inside its bound.
func (f *cimdFetcher) store(id string, e *cimdEntry, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.entries[id]; !ok && len(f.entries) >= cimdCacheEntries {
		for key, old := range f.entries {
			if !now.Before(old.validated.Add(f.ceiling)) {
				delete(f.entries, key)
			}
		}
		if len(f.entries) >= cimdCacheEntries {
			oldest := ""
			var at time.Time
			for key, old := range f.entries {
				if oldest == "" || old.validated.Before(at) {
					oldest, at = key, old.validated
				}
			}
			delete(f.entries, oldest)
		}
	}
	f.entries[id] = e
}

// drop removes one entry.
func (f *cimdFetcher) drop(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, id)
}

// cacheLifetime reads the lifetime of a response from Cache-Control, or from
// Expires when Cache-Control names no max-age. Headers that name no lifetime,
// or that forbid caching, give zero.
func cacheLifetime(h http.Header, now time.Time) time.Duration {
	maxAge := -1
	for _, directive := range strings.Split(h.Get("Cache-Control"), ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
		switch strings.ToLower(name) {
		case "no-store", "no-cache":
			return 0
		case "max-age":
			if v, err := strconv.Atoi(strings.Trim(value, `"`)); err == nil && v >= 0 {
				maxAge = v
			}
		}
	}
	if maxAge >= 0 {
		lifetime := time.Duration(maxAge) * time.Second
		if age, err := strconv.Atoi(h.Get("Age")); err == nil && age > 0 {
			lifetime -= time.Duration(age) * time.Second
		}
		return lifetime
	}
	if raw := h.Get("Expires"); raw != "" {
		expires, err := http.ParseTime(raw)
		if err != nil {
			return 0
		}
		return expires.Sub(now)
	}
	return 0
}

// cimdClient validates a document and returns its client.
func (p *Plugin) cimdClient(id string, body []byte) (client, error) {
	u, err := checkCIMDClientID(id)
	if err != nil {
		return client{}, err
	}
	var doc cimdDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return client{}, refuseCIMD("the metadata document is no JSON object")
	}
	if doc.ClientID != id {
		return client{}, refuseCIMD("the metadata document names another client identifier")
	}
	if len(doc.ClientSecret) > 0 || len(doc.ClientSecretExpiresAt) > 0 {
		return client{}, refuseCIMD("the metadata document carries a client secret")
	}
	if doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != AuthNone {
		return client{}, refuseCIMD("a metadata document client authenticates with the method none only")
	}
	if len(doc.RedirectURIs) == 0 {
		return client{}, refuseCIMD("the metadata document names no redirect URI")
	}
	for _, uri := range doc.RedirectURIs {
		if err := p.checkRedirectURI(uri); err != nil {
			return client{}, refuseCIMD("the metadata document: %s", err.Error())
		}
	}
	for _, rt := range doc.ResponseTypes {
		if rt != "code" {
			return client{}, refuseCIMD("the server issues a code and nothing else")
		}
	}
	grants := doc.GrantTypes
	if len(grants) == 0 {
		grants = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	kept := make([]string, 0, len(grants))
	for _, g := range grants {
		// A public client runs no client credentials grant, and an unknown
		// grant drops out as it does at the registration route.
		if g == GrantAuthorizationCode || g == GrantRefreshToken {
			kept = append(kept, g)
		}
	}
	if !hasGrant(kept, GrantAuthorizationCode) {
		return client{}, refuseCIMD("the metadata document names no authorization code grant")
	}
	scopes := p.scopes
	if doc.Scope != "" {
		// The document serves every authorization server, so a scope that
		// this server does not offer drops out instead of refusing the client.
		scopes = nil
		for _, s := range strings.Fields(doc.Scope) {
			if p.knownScope(s) && !contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
	}
	name := strings.TrimSpace(doc.ClientName)
	if name == "" {
		name = u.Host
	}
	if utf8.RuneCountInString(name) > cimdMaxNameLength {
		name = string([]rune(name)[:cimdMaxNameLength])
	}
	logo := ""
	if l, err := url.Parse(doc.LogoURI); err == nil && l.Scheme == "https" && l.Host != "" {
		logo = doc.LogoURI
	}
	return client{
		ClientID:     id,
		Name:         name,
		LogoURI:      logo,
		RedirectURIs: doc.RedirectURIs,
		GrantTypes:   kept,
		Scopes:       scopes,
		AuthMethod:   AuthNone,
		Kind:         kindCIMD,
		Host:         u.Host,
	}, nil
}
