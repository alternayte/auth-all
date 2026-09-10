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
	// ErrNoPasswordCredential reports that the account has no password. An
	// OAuth-only user reaches it.
	ErrNoPasswordCredential = apierr.ErrNoPasswordCredential

	// Re-exported errors of the v0.3.0 release.
	ErrInsufficientRole       = apierr.ErrInsufficientRole
	ErrRoleUnknown            = apierr.ErrRoleUnknown
	ErrRoleNotAllowed         = apierr.ErrRoleNotAllowed
	ErrUserDisabled           = apierr.ErrUserDisabled
	ErrPasswordChangeRequired = apierr.ErrPasswordChangeRequired
	ErrLastAdmin              = apierr.ErrLastAdmin
	ErrAPIKeyExpiryTooLong    = apierr.ErrAPIKeyExpiryTooLong
	ErrAPIKeyExpiryRequired   = apierr.ErrAPIKeyExpiryRequired
)

func isNotFound(err error) bool { return errors.Is(err, store.ErrNotFound) }

func isConflict(err error) bool { return errors.Is(err, store.ErrConflict) }

func asPublic(err error, dst **apierr.Error) bool { return errors.As(err, dst) }
