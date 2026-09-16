// Package jws signs and verifies the compact JSON Web Signatures that the
// Auth-All authorization server issues. It supports ES256 and RS256, and it
// reads the public JSON Web Key forms of both.
package jws

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ErrInvalidSignature reports a token that fails any verification step.
var ErrInvalidSignature = errors.New("authall/jws: the signature is invalid")

// Algorithms this package supports.
const (
	ES256 = "ES256"
	RS256 = "RS256"
)

// Key is one signing key with its identifier.
type Key struct {
	ID        string
	Algorithm string
	Private   crypto.Signer
}

// Generate returns a new key of the algorithm.
func Generate(algorithm, id string) (*Key, error) {
	switch algorithm {
	case ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &Key{ID: id, Algorithm: ES256, Private: k}, nil
	case RS256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		return &Key{ID: id, Algorithm: RS256, Private: k}, nil
	default:
		return nil, fmt.Errorf("authall/jws: unsupported algorithm %q", algorithm)
	}
}

// Encode returns the base64url form without padding.
func Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Decode reads the base64url form without padding.
func Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// Sign returns the compact serialization of the claims with the token type in
// the header.
func (k *Key) Sign(typ string, claims any) (string, error) {
	header := map[string]string{"alg": k.Algorithm, "kid": k.ID, "typ": typ}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := Encode(h) + "." + Encode(p)
	sum := sha256.Sum256([]byte(signing))
	switch k.Algorithm {
	case ES256:
		priv, ok := k.Private.(*ecdsa.PrivateKey)
		if !ok {
			return "", ErrInvalidSignature
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
		if err != nil {
			return "", err
		}
		// The JWS form is the fixed-width concatenation of r and s, not the
		// ASN.1 form that ecdsa.SignASN1 returns.
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return signing + "." + Encode(out), nil
	case RS256:
		sig, err := k.Private.Sign(rand.Reader, sum[:], crypto.SHA256)
		if err != nil {
			return "", err
		}
		return signing + "." + Encode(sig), nil
	default:
		return "", fmt.Errorf("authall/jws: unsupported algorithm %q", k.Algorithm)
	}
}

// PublicJWK returns the public JSON Web Key of the key.
func (k *Key) PublicJWK() (string, error) {
	jwk, err := PublicJWK(k.Private.Public(), k.Algorithm, k.ID)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// PublicJWK returns the public JSON Web Key of a public key.
func PublicJWK(pub crypto.PublicKey, algorithm, id string) (map[string]any, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		return map[string]any{
			"kty": "EC", "crv": "P-256", "alg": algorithm, "use": "sig", "kid": id,
			"x": Encode(bytesOf(p.X, 32)), "y": Encode(bytesOf(p.Y, 32)),
		}, nil
	case *rsa.PublicKey:
		e := make([]byte, 4)
		binary.BigEndian.PutUint32(e, uint32(p.E))
		return map[string]any{
			"kty": "RSA", "alg": algorithm, "use": "sig", "kid": id,
			"n": Encode(p.N.Bytes()), "e": Encode(trimLeadingZeros(e)),
		}, nil
	default:
		return nil, fmt.Errorf("authall/jws: unsupported public key %T", pub)
	}
}

// bytesOf returns the fixed-width big-endian form of v.
func bytesOf(v *big.Int, width int) []byte {
	out := make([]byte, width)
	v.FillBytes(out)
	return out
}

func trimLeadingZeros(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// Header holds the fields of a compact header that a verifier reads.
type Header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
	// JWK carries the proof key of a DPoP proof.
	JWK map[string]any `json:"jwk"`
}

// Parse splits a compact token and returns the header and the raw payload. It
// verifies nothing.
func Parse(token string) (Header, []byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, nil, ErrInvalidSignature
	}
	rawHeader, err := Decode(parts[0])
	if err != nil {
		return Header{}, nil, ErrInvalidSignature
	}
	var h Header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return Header{}, nil, ErrInvalidSignature
	}
	payload, err := Decode(parts[1])
	if err != nil {
		return Header{}, nil, ErrInvalidSignature
	}
	return h, payload, nil
}

// Verify checks the signature of a compact token against a public key and
// returns the payload.
func Verify(token string, pub crypto.PublicKey) ([]byte, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidSignature
	}
	header, payload, err := Parse(token)
	if err != nil {
		return nil, err
	}
	sig, err := Decode(parts[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch header.Algorithm {
	case ES256:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return nil, ErrInvalidSignature
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(key, sum[:], r, s) {
			return nil, ErrInvalidSignature
		}
		return payload, nil
	case RS256:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, ErrInvalidSignature
		}
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
			return nil, ErrInvalidSignature
		}
		return payload, nil
	default:
		return nil, ErrInvalidSignature
	}
}

// PublicKeyFromJWK reads the public key of a JSON Web Key. It accepts the two
// key types this package signs with.
func PublicKeyFromJWK(jwk map[string]any) (crypto.PublicKey, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		if crv, _ := jwk["crv"].(string); crv != "P-256" {
			return nil, ErrInvalidSignature
		}
		x, err := decodeCoordinate(jwk["x"])
		if err != nil {
			return nil, err
		}
		y, err := decodeCoordinate(jwk["y"])
		if err != nil {
			return nil, err
		}
		// The ecdh package validates the point. A point that is not on the
		// curve fails here, before any verification uses it.
		uncompressed := make([]byte, 1, 65)
		uncompressed[0] = 4
		uncompressed = append(uncompressed, bytesOf(x, 32)...)
		uncompressed = append(uncompressed, bytesOf(y, 32)...)
		if _, err := ecdh.P256().NewPublicKey(uncompressed); err != nil {
			return nil, ErrInvalidSignature
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case "RSA":
		n, err := decodeCoordinate(jwk["n"])
		if err != nil {
			return nil, err
		}
		e, err := decodeCoordinate(jwk["e"])
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() > 1<<31-1 {
			return nil, ErrInvalidSignature
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	default:
		return nil, ErrInvalidSignature
	}
}

func decodeCoordinate(v any) (*big.Int, error) {
	s, ok := v.(string)
	if !ok || s == "" {
		return nil, ErrInvalidSignature
	}
	raw, err := Decode(s)
	if err != nil {
		return nil, ErrInvalidSignature
	}
	return new(big.Int).SetBytes(raw), nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of a public JSON Web Key.
// DPoP uses it as the confirmation value of a bound token.
func Thumbprint(jwk map[string]any) (string, error) {
	var canonical string
	switch kty, _ := jwk["kty"].(string); kty {
	case "EC":
		crv, _ := jwk["crv"].(string)
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if crv == "" || x == "" || y == "" {
			return "", ErrInvalidSignature
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y)
	case "RSA":
		e, _ := jwk["e"].(string)
		n, _ := jwk["n"].(string)
		if e == "" || n == "" {
			return "", ErrInvalidSignature
		}
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
	default:
		return "", ErrInvalidSignature
	}
	sum := sha256.Sum256([]byte(canonical))
	return Encode(sum[:]), nil
}
