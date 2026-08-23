// Package jwt verifies the compact RS256 identity tokens of OpenID Connect
// providers. It supports the single algorithm Auth-All accepts.
package jwt

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrInvalidToken reports a token that fails any validation step.
var ErrInvalidToken = errors.New("authall/jwt: the identity token is invalid")

// Claims are the identity token claims Auth-All reads.
type Claims struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Audience      any    `json:"aud"`
	Expiry        int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// VerifiedEmail reports the boolean form of the email_verified claim, which
// some providers send as a string.
func (c Claims) VerifiedEmail() bool {
	switch v := c.EmailVerified.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func (c Claims) hasAudience(aud string) bool {
	switch v := c.Audience.(type) {
	case string:
		return v == aud
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == aud {
				return true
			}
		}
	}
	return false
}

// Verification describes the required checks.
type Verification struct {
	Issuer   string
	Audience string
	Nonce    string
	Now      time.Time
	// Leeway absorbs small clock differences.
	Leeway time.Duration
}

// KeySet fetches and caches the public keys of one provider.
type KeySet struct {
	url    string
	client *http.Client
	ttl    time.Duration

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// NewKeySet returns a key set for a JWKS URL.
func NewKeySet(url string, client *http.Client) *KeySet {
	if client == nil {
		client = http.DefaultClient
	}
	return &KeySet{url: url, client: client, ttl: 10 * time.Minute}
}

type jwks struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (k *KeySet) key(ctx context.Context, kid string, now time.Time) (*rsa.PublicKey, error) {
	k.mu.Lock()
	cached, ok := k.keys[kid]
	fresh := now.Sub(k.fetched) < k.ttl
	k.mu.Unlock()
	if ok && fresh {
		return cached, nil
	}
	keys, err := k.fetch(ctx)
	if err != nil {
		if ok {
			return cached, nil
		}
		return nil, err
	}
	k.mu.Lock()
	k.keys = keys
	k.fetched = now
	k.mu.Unlock()
	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: unknown key id", ErrInvalidToken)
	}
	return key, nil
}

func (k *KeySet) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authall/jwt: the key set request returned status %d", resp.StatusCode)
	}
	var doc jwks
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, key := range doc.Keys {
		if key.Kty != "RSA" || (key.Alg != "" && key.Alg != "RS256") {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(key.N, "="))
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(key.E, "="))
		if err != nil {
			continue
		}
		out[key.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(bigEndian(eBytes))}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("authall/jwt: the key set contains no usable RSA key")
	}
	return out, nil
}

func bigEndian(b []byte) uint64 {
	padded := make([]byte, 8)
	copy(padded[8-len(b):], b)
	return binary.BigEndian.Uint64(padded)
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Verify checks the signature and the required claims of an identity token.
func (k *KeySet) Verify(ctx context.Context, token string, v Verification) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: malformed token", ErrInvalidToken)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed header", ErrInvalidToken)
	}
	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("%w: malformed header", ErrInvalidToken)
	}
	if h.Alg != "RS256" {
		return nil, fmt.Errorf("%w: unsupported algorithm", ErrInvalidToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed payload", ErrInvalidToken)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: malformed signature", ErrInvalidToken)
	}
	key, err := k.key(ctx, h.Kid, v.Now)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
		return nil, fmt.Errorf("%w: the signature does not verify", ErrInvalidToken)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: malformed claims", ErrInvalidToken)
	}
	if claims.Issuer != v.Issuer {
		return nil, fmt.Errorf("%w: unexpected issuer", ErrInvalidToken)
	}
	if !claims.hasAudience(v.Audience) {
		return nil, fmt.Errorf("%w: unexpected audience", ErrInvalidToken)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: the subject is empty", ErrInvalidToken)
	}
	if claims.Expiry == 0 || v.Now.Add(-v.Leeway).After(time.Unix(claims.Expiry, 0)) {
		return nil, fmt.Errorf("%w: the token is expired", ErrInvalidToken)
	}
	if v.Nonce != "" && claims.Nonce != v.Nonce {
		return nil, fmt.Errorf("%w: unexpected nonce", ErrInvalidToken)
	}
	return &claims, nil
}
