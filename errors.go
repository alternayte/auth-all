package authall

import (
	"errors"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/store"
)

// Error is the public Auth-All error type. Its code is part of the public API
// compatibility surface.
type Error = apierr.Error

// Code is a stable machine-readable error code.
type Code = apierr.Code

// Re-exported public errors.
var (
	ErrInvalidRequest     = apierr.ErrInvalidRequest
	ErrInvalidCredentials = apierr.ErrInvalidCredentials
	ErrEmailAlreadyExists = apierr.ErrEmailAlreadyExists
	ErrWeakPassword       = apierr.ErrWeakPassword
	ErrInvalidToken       = apierr.ErrInvalidToken
	ErrUnauthorized       = apierr.ErrUnauthorized
	ErrForbidden          = apierr.ErrForbidden
	ErrNotFound           = apierr.ErrNotFound
	ErrLastAuthMethod     = apierr.ErrLastAuthMethod
)

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

func isConflict(err error) bool { return errors.Is(err, store.ErrConflict) }

func asPublic(err error, dst **apierr.Error) bool { return errors.As(err, dst) }
