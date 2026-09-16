package oauthprovider

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/internal/jws"
	"github.com/alternayte/auth-all/store"
)

// wrap encrypts a private key with the key encryption key of the host. The
// nonce starts the ciphertext, so a database dump carries no usable key.
func (p *Plugin) wrap(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// unwrap decrypts a private key.
func (p *Plugin) unwrap(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("authall/oauthprovider: the wrapped key is truncated")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)
}

// signingKey returns the current signing key. It generates the first key when
// the table is empty, so a fresh deployment needs no separate step.
func (p *Plugin) signingKey(ctx context.Context) (*jws.Key, error) {
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	if p.signer != nil {
		return p.signer, nil
	}
	if err := p.loadKeys(ctx); err != nil {
		return nil, err
	}
	if p.signer != nil {
		return p.signer, nil
	}
	if err := p.generateKey(ctx, false); err != nil {
		// A concurrent process can have inserted the first key. Read again
		// before the call fails.
		if loadErr := p.loadKeys(ctx); loadErr == nil && p.signer != nil {
			return p.signer, nil
		}
		return nil, err
	}
	return p.signer, nil
}

// loadKeys fills the signer and the verifiers from the rows. The caller holds
// the lock.
func (p *Plugin) loadKeys(ctx context.Context) error {
	rows, err := p.rows.ListOAuthKeys(ctx)
	if err != nil {
		return err
	}
	verifiers := map[string]any{}
	var signer *jws.Key
	for _, row := range rows {
		var jwk map[string]any
		if err := json.Unmarshal([]byte(row.PublicJWK), &jwk); err != nil {
			return err
		}
		pub, err := jws.PublicKeyFromJWK(jwk)
		if err != nil {
			return err
		}
		verifiers[row.ID] = pub
		if row.RetiredAt != nil || signer != nil || row.Algorithm != p.algorithm {
			continue
		}
		raw, err := p.unwrap(row.WrappedPrivate)
		if err != nil {
			return err
		}
		private, err := x509.ParsePKCS8PrivateKey(raw)
		if err != nil {
			return err
		}
		signerKey, err := signerOf(private, row.Algorithm, row.ID)
		if err != nil {
			return err
		}
		signer = signerKey
	}
	p.verifiers = verifiers
	p.signer = signer
	return nil
}

// signerOf returns the signing key of a parsed private key.
func signerOf(private any, algorithm, id string) (*jws.Key, error) {
	key, ok := private.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("authall/oauthprovider: the stored key %q signs nothing", id)
	}
	return &jws.Key{ID: id, Algorithm: algorithm, Private: key}, nil
}

// generateKey inserts a new key. The caller holds the lock. A rotation retires
// every other key, and the retired key stays in the key set so a cached copy
// still verifies.
func (p *Plugin) generateKey(ctx context.Context, retireOthers bool) error {
	key, err := jws.Generate(p.algorithm, uuid.NewString())
	if err != nil {
		return err
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key.Private)
	if err != nil {
		return err
	}
	wrapped, err := p.wrap(raw)
	if err != nil {
		return err
	}
	public, err := key.PublicJWK()
	if err != nil {
		return err
	}
	row := &store.OAuthKey{ID: key.ID, Algorithm: key.Algorithm, WrappedPrivate: wrapped,
		PublicJWK: public, CreatedAt: p.now()}
	if err := p.rows.CreateOAuthKey(ctx, row); err != nil {
		return err
	}
	if retireOthers {
		if err := p.rows.RetireOAuthKeys(ctx, key.ID, p.now()); err != nil {
			return err
		}
	}
	return p.loadKeys(ctx)
}

// Rotate issues a new signing key and retires every earlier key. The host
// calls it, because Auth-All runs no background work of its own. The retired
// key stays in the published key set, so a relying party with a cached key set
// keeps verifying the tokens it holds.
func (p *Plugin) Rotate(ctx context.Context) error {
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	p.signer = nil
	return p.generateKey(ctx, true)
}

// verifier returns the public key of one key identifier.
func (p *Plugin) verifier(ctx context.Context, kid string) (any, error) {
	p.keyMu.Lock()
	pub, ok := p.verifiers[kid]
	p.keyMu.Unlock()
	if ok {
		return pub, nil
	}
	p.keyMu.Lock()
	defer p.keyMu.Unlock()
	if err := p.loadKeys(ctx); err != nil {
		return nil, err
	}
	pub, ok = p.verifiers[kid]
	if !ok {
		return nil, errors.New("authall/oauthprovider: the key is unknown")
	}
	return pub, nil
}

// keySet returns the published JSON Web Key Set.
func (p *Plugin) keySet(ctx context.Context) (map[string]any, error) {
	if _, err := p.signingKey(ctx); err != nil {
		return nil, err
	}
	rows, err := p.rows.ListOAuthKeys(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		var jwk map[string]any
		if err := json.Unmarshal([]byte(row.PublicJWK), &jwk); err != nil {
			return nil, err
		}
		keys = append(keys, jwk)
	}
	return map[string]any{"keys": keys}, nil
}

// handleJWKS serves the key set.
func (p *Plugin) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := p.keySet(r.Context())
	if err != nil {
		p.writeOAuthError(w, http.StatusInternalServerError, errServerError, "the key set is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	p.svc.HTTP().WriteJSON(w, http.StatusOK, set)
}
