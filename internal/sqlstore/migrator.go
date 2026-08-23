package sqlstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/alternayte/auth-all/schema"
)

type migrator struct{ s *Store }

func (m *migrator) Dialect() schema.Dialect { return m.s.d.Name }

// Plan returns the statements that the database does not record as applied.
func (m *migrator) Plan(ctx context.Context, s *schema.Schema) ([]schema.Statement, error) {
	all, err := schema.Render(m.s.d.Name, s)
	if err != nil {
		return nil, err
	}
	applied, err := m.applied(ctx)
	if err != nil {
		return nil, err
	}
	var pending []schema.Statement
	for _, st := range all {
		if st.ID == "table:"+schema.MigrationTable {
			continue
		}
		if !applied[st.ID] {
			pending = append(pending, st)
		}
	}
	return pending, nil
}

// Apply runs every pending statement and records it.
func (m *migrator) Apply(ctx context.Context, s *schema.Schema) ([]schema.Statement, error) {
	all, err := schema.Render(m.s.d.Name, s)
	if err != nil {
		return nil, err
	}
	// The migration record table always exists first.
	if _, err := m.s.exec(ctx, all[0].SQL); err != nil {
		return nil, err
	}
	pending, err := m.Plan(ctx, s)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	for _, st := range pending {
		if _, err := m.s.exec(ctx, st.SQL); err != nil {
			return nil, fmt.Errorf("authall: apply %s: %w", st.ID, err)
		}
		if _, err := m.s.exec(ctx,
			"INSERT INTO "+schema.MigrationTable+" (id, applied_at) VALUES (?, ?)",
			st.ID, m.s.bindTime(now)); err != nil {
			return nil, err
		}
	}
	return pending, nil
}

// Check reports an actionable error when the schema is missing or outdated.
func (m *migrator) Check(ctx context.Context, s *schema.Schema) error {
	pending, err := m.Plan(ctx, s)
	if err != nil {
		return fmt.Errorf("authall: cannot read the Auth-All schema state: %w. Run: auth-all migrate", err)
	}
	if len(pending) == 0 {
		return nil
	}
	ids := make([]string, 0, len(pending))
	for _, st := range pending {
		ids = append(ids, st.ID)
	}
	return fmt.Errorf("authall: the database schema is outdated. Missing: %s. Run: auth-all migrate",
		strings.Join(ids, ", "))
}

func (m *migrator) applied(ctx context.Context) (map[string]bool, error) {
	out := map[string]bool{}
	rows, err := m.s.query(ctx, "SELECT id FROM "+schema.MigrationTable)
	if err != nil {
		// A missing record table means nothing is applied yet.
		return out, nil
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}
