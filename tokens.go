package authall

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/internal/crypto"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// issueToken creates a one-time token. The plaintext value exists only in the
// return value. The database keeps the hash.
func (a *Auth) issueToken(ctx context.Context, in plugin.IssueTokenInput) (string, *store.Token, error) {
	if in.Kind == "" {
		return "", nil, apierr.ErrInternal.WithMessage("An internal error occurred.")
	}
	if in.TTL <= 0 {
		in.TTL = time.Hour
	}
	plaintext, err := crypto.NewToken()
	if err != nil {
		return "", nil, apierr.ErrInternal.WithCause(err)
	}
	now := a.cfg.now()
	tok := &store.Token{
		ID:         uuid.NewString(),
		UserID:     in.UserID,
		Kind:       in.Kind,
		Identifier: in.Identifier,
		TokenHash:  crypto.HashToken(plaintext),
		CreatedAt:  now,
		ExpiresAt:  now.Add(in.TTL),
	}
	err = a.cfg.store.Transaction(ctx, func(tx store.Store) error {
		if in.ReplaceExisting && in.Identifier != "" {
			if err := tx.Tokens().DeleteByIdentifier(ctx, in.Kind, in.Identifier); err != nil {
				return err
			}
		}
		return tx.Tokens().Create(ctx, tok)
	})
	if err != nil {
		return "", nil, publicError(err)
	}
	return plaintext, tok, nil
}

// consumeToken atomically consumes a one-time token. A replay, an expired
// token, and a malformed token all produce apierr.ErrInvalidToken.
func (a *Auth) consumeToken(ctx context.Context, kind, plaintext string) (*store.Token, error) {
	if plaintext == "" {
		return nil, apierr.ErrInvalidToken
	}
	tok, err := a.cfg.store.Tokens().Consume(ctx, kind, crypto.HashToken(plaintext), a.cfg.now())
	if err != nil {
		if isNotFound(err) {
			return nil, apierr.ErrInvalidToken
		}
		return nil, apierr.ErrInternal.WithCause(err)
	}
	return tok, nil
}
