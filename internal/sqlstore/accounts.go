package sqlstore

import (
	"context"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

type accountStore struct{ s *Store }

const accountColumns = "id, user_id, provider, provider_account_id, created_at, updated_at"

func (a *accountStore) Create(ctx context.Context, m *store.Account) error {
	_, err := a.s.exec(ctx,
		"INSERT INTO "+schema.TableAccounts+" ("+accountColumns+") VALUES (?, ?, ?, ?, ?, ?)",
		m.ID, m.UserID, m.Provider, m.ProviderAccountID, a.s.bindTime(m.CreatedAt), a.s.bindTime(m.UpdatedAt))
	return a.s.mapErr(err)
}

func (a *accountStore) GetByProviderAccount(ctx context.Context, provider, providerAccountID string) (*store.Account, error) {
	row := a.s.queryRow(ctx,
		"SELECT "+accountColumns+" FROM "+schema.TableAccounts+" WHERE provider = ? AND provider_account_id = ?",
		provider, providerAccountID)
	var m store.Account
	if err := row.Scan(&m.ID, &m.UserID, &m.Provider, &m.ProviderAccountID, timeScan{&m.CreatedAt}, timeScan{&m.UpdatedAt}); err != nil {
		return nil, a.s.mapErr(err)
	}
	return &m, nil
}

func (a *accountStore) ListByUser(ctx context.Context, userID string) ([]store.Account, error) {
	rows, err := a.s.query(ctx,
		"SELECT "+accountColumns+" FROM "+schema.TableAccounts+" WHERE user_id = ? ORDER BY provider", userID)
	if err != nil {
		return nil, a.s.mapErr(err)
	}
	defer rows.Close()
	var out []store.Account
	for rows.Next() {
		var m store.Account
		if err := rows.Scan(&m.ID, &m.UserID, &m.Provider, &m.ProviderAccountID, timeScan{&m.CreatedAt}, timeScan{&m.UpdatedAt}); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (a *accountStore) Delete(ctx context.Context, userID, provider string) error {
	res, err := a.s.exec(ctx,
		"DELETE FROM "+schema.TableAccounts+" WHERE user_id = ? AND provider = ?", userID, provider)
	if err != nil {
		return a.s.mapErr(err)
	}
	return requireAffected(res)
}
