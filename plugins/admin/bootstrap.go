package admin

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// bootstrapVersion is the version of the migration unit of the guard table.
const bootstrapVersion = "20260910000004"

// bootstrapRowID is the primary key of the single guard row.
const bootstrapRowID = "admin"

// bootstrapTable returns the guard table of the bootstrap.
func bootstrapTable(o schema.Options) schema.Table {
	n := schema.TableNames(o)
	return schema.Table{
		Name: n.Bootstrap,
		Columns: []schema.Column{
			// The identifier is always "admin", so a second insert conflicts.
			{Name: "id", Type: schema.TypeText, PrimaryKey: true},
			{Name: "user_id", Type: idType(o)},
			{Name: "created_at", Type: schema.TypeTimestamp},
		},
	}
}

// idType returns the physical type of an identifier column.
func idType(o schema.Options) schema.Type {
	if o.IDType == schema.IDUUID {
		return schema.TypeUUID
	}
	return schema.TypeText
}

// bootstrapUnit returns the migration unit of the guard table.
func bootstrapUnit(o schema.Options) (schema.Unit, error) {
	return schema.TableUnit(bootstrapVersion, ID, "authall_bootstrap",
		[]schema.Dialect{schema.Postgres, schema.SQLite}, []schema.Table{bootstrapTable(o)})
}

// Credentials name the first administrator.
type Credentials struct {
	Email    string
	Password string
	Name     string
	// TemporaryPassword makes the first administrator change the password
	// before it reaches any protected route. The default is false.
	TemporaryPassword bool
}

// Bootstrap creates the first administrator when the users table is empty.
//
// It returns false and changes nothing when any user exists. Two instances can
// call it at the same time, and at most one user appears, because the guard
// row has one primary key.
//
// Auth-All never calls Bootstrap on its own. Construction has no side effect,
// so a replica start changes no user.
func (p *Plugin) Bootstrap(ctx context.Context, creds Credentials) (bool, error) {
	if err := p.ready(); err != nil {
		return false, err
	}
	if strings.TrimSpace(creds.Email) == "" {
		return false, apierr.ErrInvalidRequest.WithMessage("The email address is required.")
	}
	// The policy check runs before any write, so a weak password creates no
	// user and no guard row.
	hash, err := p.hashPassword(creds.Password)
	if err != nil {
		return false, err
	}
	existing, err := p.anyUserExists(ctx)
	if err != nil {
		return false, err
	}
	if existing {
		return false, nil
	}

	// The system actor names an operation that no request started.
	ctx = events.WithActor(ctx, events.Actor{ID: events.ActorSystem})
	user, err := p.users.Create(ctx, plugin.CreateUserInput{
		Email: creds.Email, DisplayName: creds.Name,
	})
	if err != nil {
		if errors.Is(err, apierr.ErrEmailAlreadyExists) {
			return false, nil
		}
		return false, err
	}
	now := p.now()
	err = p.store.Transaction(ctx, func(tx store.Store) error {
		if err := p.claimBootstrap(ctx, tx, user.ID, now); err != nil {
			return err
		}
		if err := tx.Users().SetCredential(ctx, &store.Credential{
			UserID: user.ID, PasswordHash: hash, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			return err
		}
		user.Role = p.adminRole
		user.MustChangePassword = creds.TemporaryPassword
		user.UpdatedAt = now
		return tx.Users().Update(ctx, user)
	})
	if err != nil {
		if errors.Is(err, errBootstrapTaken) {
			// A second instance won the race. The user of this call is a
			// leftover row with no credential, so it authenticates nobody.
			_ = p.store.Users().Delete(ctx, user.ID)
			return false, nil
		}
		return false, publicError(err)
	}
	p.emit(ctx, events.UserCreated, user, map[string]any{"role": p.adminRole, "bootstrap": true})
	return true, nil
}

// errBootstrapTaken reports that another instance already claimed the guard
// row.
var errBootstrapTaken = errors.New("authall/admin: the bootstrap row exists")

// claimBootstrap inserts the guard row. A second insert conflicts on the
// primary key, so exactly one caller continues.
func (p *Plugin) claimBootstrap(ctx context.Context, tx store.Store, userID string, now time.Time) error {
	writer, ok := tx.(store.RowWriter)
	if !ok {
		return apierr.ErrInternal.WithCause(errors.New("authall/admin: the store writes no guard row"))
	}
	table := schema.TableNames(p.schemaOptions).Bootstrap
	err := writer.InsertRow(ctx, table,
		[]string{"id", "user_id", "created_at"},
		[]any{bootstrapRowID, userID, now})
	if errors.Is(err, store.ErrConflict) {
		return errBootstrapTaken
	}
	return err
}

// anyUserExists reports whether the users table holds a row.
func (p *Plugin) anyUserExists(ctx context.Context) (bool, error) {
	admins, ok := p.store.(store.UserAdminStore)
	if !ok {
		return false, apierr.ErrInternal.WithCause(errors.New("authall/admin: the store lists no users"))
	}
	users, _, err := admins.ListUsers(ctx, store.UserListFilter{Limit: 1})
	if err != nil {
		return false, publicError(err)
	}
	return len(users) > 0, nil
}
