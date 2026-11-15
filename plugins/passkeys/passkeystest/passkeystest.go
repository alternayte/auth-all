// Package passkeystest provides a virtual WebAuthn authenticator for Go tests.
//
// A host test drives the passkey ceremonies of the passkeys plugin with no
// browser: it posts the begin route, hands the options to the authenticator,
// and posts the returned credential to the finish route.
//
//	auth := passkeystest.New("example.com", "https://example.com")
//	begin := post("/passkeys/register/begin", nil)
//	credential, err := auth.Register(begin.Options)
//	post("/passkeys/register/finish", map[string]any{
//	    "ceremony": begin.Ceremony, "name": "laptop", "credential": credential,
//	})
//
// The authenticator creates ES256 keys, signs with the attestation format
// "none", keeps a sign counter for each credential, and sets the
// user-verified flag unless the test turns it off. It is not for production
// use: the private keys live in memory.
package passkeystest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/fxamacker/cbor/v2"
)

// Flag bits of the authenticator data.
const (
	flagUserPresent    = 0x01
	flagUserVerified   = 0x04
	flagBackupEligible = 0x08
	flagBackupState    = 0x10
	flagAttestedData   = 0x40
)

// Authenticator is a virtual passkey authenticator for one relying party. It
// is safe for concurrent use.
type Authenticator struct {
	rpID   string
	origin string

	mu           sync.Mutex
	userVerified bool
	synced       bool
	credentials  []*credential
}

// credential is one discoverable credential that the authenticator holds.
type credential struct {
	id         []byte
	userHandle []byte
	key        *ecdsa.PrivateKey
	count      uint32
}

// New returns an authenticator for one RP ID. Origin is the origin that the
// client data names, for example "https://app.example.com".
func New(rpID, origin string) *Authenticator {
	return &Authenticator{rpID: rpID, origin: origin, userVerified: true}
}

// SetUserVerified sets the user-verified flag of later responses. A false
// value acts as a security key with no PIN check.
func (a *Authenticator) SetUserVerified(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.userVerified = v
}

// SetSynced makes later credentials backup eligible and backed up, as a
// synced passkey of a password manager reports, and keeps their sign counter
// at zero.
func (a *Authenticator) SetSynced(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.synced = v
}

// SetSignCount sets the sign counter of every credential. A value below the
// counter that the server holds acts as a cloned authenticator.
func (a *Authenticator) SetSignCount(n uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.credentials {
		c.count = n
	}
}

// creationOptions is the part of the creation options that the authenticator
// reads.
type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

// requestOptions is the part of the request options that the authenticator
// reads.
type requestOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	} `json:"publicKey"`
}

// Register answers the creation options of a registration begin route: the
// "options" member of its response. It returns the credential in the JSON form
// that the finish route takes.
func (a *Authenticator) Register(options json.RawMessage) (json.RawMessage, error) {
	var opts creationOptions
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, fmt.Errorf("passkeystest: decode the creation options: %w", err)
	}
	if opts.PublicKey.Challenge == "" {
		return nil, errors.New("passkeystest: the creation options hold no challenge")
	}
	rpID := opts.PublicKey.RP.ID
	if rpID == "" {
		rpID = a.rpID
	}
	userHandle, err := decodeB64(opts.PublicKey.User.ID)
	if err != nil {
		return nil, fmt.Errorf("passkeystest: decode the user handle: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for _, excluded := range opts.PublicKey.ExcludeCredentials {
		for _, c := range a.credentials {
			if b64(c.id) == trimPad(excluded.ID) {
				return nil, errors.New("passkeystest: the authenticator holds an excluded credential")
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	c := &credential{id: id, userHandle: userHandle, key: key}

	cose, err := coseKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	flags := byte(flagUserPresent | flagAttestedData)
	flags |= a.flags()
	authData := authenticatorData(rpID, flags, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID of no model.
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id)))
	authData = append(authData, id...)
	authData = append(authData, cose...)

	attestation, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, err
	}
	clientData, err := json.Marshal(map[string]any{
		"type": "webauthn.create", "challenge": trimPad(opts.PublicKey.Challenge),
		"origin": a.origin, "crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	a.credentials = append(a.credentials, c)
	return json.Marshal(map[string]any{
		"id":    b64(id),
		"rawId": b64(id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"attestationObject": b64(attestation),
			"transports":        []string{"internal"},
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
}

// SignIn answers the request options of a sign-in begin route with the newest
// credential, as a browser does for a discoverable request. It returns the
// assertion in the JSON form that the finish route takes.
func (a *Authenticator) SignIn(options json.RawMessage) (json.RawMessage, error) {
	var opts requestOptions
	if err := json.Unmarshal(options, &opts); err != nil {
		return nil, fmt.Errorf("passkeystest: decode the request options: %w", err)
	}
	if opts.PublicKey.Challenge == "" {
		return nil, errors.New("passkeystest: the request options hold no challenge")
	}
	rpID := opts.PublicKey.RPID
	if rpID == "" {
		rpID = a.rpID
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.credentials) == 0 {
		return nil, errors.New("passkeystest: the authenticator holds no credential")
	}
	c := a.credentials[len(a.credentials)-1]
	if !a.synced {
		c.count++
	}
	authData := authenticatorData(rpID, flagUserPresent|a.flags(), c.count)
	clientData, err := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": trimPad(opts.PublicKey.Challenge),
		"origin": a.origin, "crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	clientHash := sha256.Sum256(clientData)
	signed := sha256.Sum256(append(append([]byte(nil), authData...), clientHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, c.key, signed[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id":    b64(c.id),
		"rawId": b64(c.id),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(signature),
			"userHandle":        b64(c.userHandle),
		},
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	})
}

// flags returns the verification and backup bits of the current settings. The
// caller holds the lock.
func (a *Authenticator) flags() byte {
	var f byte
	if a.userVerified {
		f |= flagUserVerified
	}
	if a.synced {
		f |= flagBackupEligible | flagBackupState
	}
	return f
}

// authenticatorData returns the RP ID hash, the flags, and the counter.
func authenticatorData(rpID string, flags byte, count uint32) []byte {
	hash := sha256.Sum256([]byte(rpID))
	out := append([]byte(nil), hash[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, count)
}

// coseKey encodes a P-256 public key as a COSE_Key of the ES256 algorithm.
func coseKey(pub *ecdsa.PublicKey) ([]byte, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	// raw is 0x04 || X || Y.
	x, y := raw[1:33], raw[33:65]
	return cbor.Marshal(map[int]any{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,
		-3: y,
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func trimPad(s string) string { return strings.TrimRight(s, "=") }

func decodeB64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(trimPad(s))
}
