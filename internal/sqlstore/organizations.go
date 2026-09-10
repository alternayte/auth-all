package sqlstore

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/alternayte/auth-all/schema"
	"github.com/alternayte/auth-all/store"
)

// maxOrgPage is the highest accepted page size of an organization list and of
// a member list.
const maxOrgPage = 200

// defaultOrgPage is the page size of a request that names none.
const defaultOrgPage = 50

// orgColumns are the Auth-All columns of the organizations table.
const orgColumns = "id, name, slug, created_at, updated_at"

// orgColumnList returns the column list of an organization row, with the
// host-owned fields at the end.
func (s *Store) orgColumnList() string {
	out := orgColumns
	for _, f := range s.orgFields {
		out += ", " + f.Name
	}
	return out
}

// scanOrgRow returns the scan targets of orgColumnList.
func (s *Store) scanOrgRow(o *store.Organization, extra []any) []any {
	targets := []any{&o.ID, &o.Name, &o.Slug, timeScan{&o.CreatedAt}, timeScan{&o.UpdatedAt}}
	for i := range s.orgFields {
		targets = append(targets, &extra[i])
	}
	return targets
}

// collectOrgExtra puts the read host-owned values in the organization.
func (s *Store) collectOrgExtra(o *store.Organization, extra []any) {
	if len(s.orgFields) == 0 {
		return
	}
	values := make(map[string]any, len(s.orgFields))
	for i, f := range s.orgFields {
		values[f.Name] = extra[i]
	}
	o.Extra = store.NewExtraFields(values)
}

// orgExtraValues returns the bound values of the host-owned fields.
func (s *Store) orgExtraValues(o *store.Organization) []any {
	out := make([]any, 0, len(s.orgFields))
	for _, f := range s.orgFields {
		value, ok := o.Extra.Get(f.Name)
		if !ok {
			out = append(out, nil)
			continue
		}
		if t, isTime := value.(time.Time); isTime {
			value = s.bindTime(t)
		}
		out = append(out, value)
	}
	return out
}

// CreateOrganization implements store.OrganizationStore.
func (s *Store) CreateOrganization(ctx context.Context, o *store.Organization) error {
	values := []any{o.ID, o.Name, o.Slug, s.bindTime(o.CreatedAt), s.bindTime(o.UpdatedAt)}
	values = append(values, s.orgExtraValues(o)...)
	placeholders := strings.TrimSuffix(strings.Repeat("?, ", len(values)), ", ")
	_, err := s.exec(ctx,
		"INSERT INTO "+s.on.Organizations+" ("+s.orgColumnList()+") VALUES ("+placeholders+")", values...)
	return s.mapErr(err)
}

// OrganizationByID implements store.OrganizationStore.
func (s *Store) OrganizationByID(ctx context.Context, id string) (*store.Organization, error) {
	return s.organization(ctx, "id = ?", id)
}

// OrganizationBySlug implements store.OrganizationStore.
func (s *Store) OrganizationBySlug(ctx context.Context, slug string) (*store.Organization, error) {
	return s.organization(ctx, "slug = ?", slug)
}

func (s *Store) organization(ctx context.Context, where string, arg any) (*store.Organization, error) {
	row := s.queryRow(ctx, "SELECT "+s.orgColumnList()+" FROM "+s.on.Organizations+" WHERE "+where, arg)
	var o store.Organization
	extra := make([]any, len(s.orgFields))
	if err := row.Scan(s.scanOrgRow(&o, extra)...); err != nil {
		return nil, s.mapErr(err)
	}
	s.collectOrgExtra(&o, extra)
	return &o, nil
}

// UpdateOrganization implements store.OrganizationStore.
func (s *Store) UpdateOrganization(ctx context.Context, o *store.Organization) error {
	set := "name = ?, slug = ?, updated_at = ?"
	values := []any{o.Name, o.Slug, s.bindTime(o.UpdatedAt)}
	extra := s.orgExtraValues(o)
	for i, f := range s.orgFields {
		set += ", " + f.Name + " = ?"
		values = append(values, extra[i])
	}
	values = append(values, o.ID)
	result, err := s.exec(ctx, "UPDATE "+s.on.Organizations+" SET "+set+" WHERE id = ?", values...)
	if err != nil {
		return s.mapErr(err)
	}
	return notFoundWhenNoRow(result)
}

// DeleteOrganization implements store.OrganizationStore.
//
// The statements remove every row that belongs to the organization, so no
// orphan survives on an engine that applies no foreign key.
func (s *Store) DeleteOrganization(ctx context.Context, id string) error {
	statements := []string{
		"DELETE FROM " + s.on.TeamMembers + " WHERE team_id IN (SELECT id FROM " + s.on.Teams + " WHERE org_id = ?)",
		"DELETE FROM " + s.on.Teams + " WHERE org_id = ?",
		"DELETE FROM " + s.on.Invitations + " WHERE org_id = ?",
		"DELETE FROM " + s.on.Roles + " WHERE org_id = ?",
		"DELETE FROM " + s.on.Members + " WHERE org_id = ?",
	}
	for _, statement := range statements {
		if _, err := s.exec(ctx, statement, id); err != nil {
			return s.mapErr(err)
		}
	}
	result, err := s.exec(ctx, "DELETE FROM "+s.on.Organizations+" WHERE id = ?", id)
	if err != nil {
		return s.mapErr(err)
	}
	return notFoundWhenNoRow(result)
}

// ListOrganizations implements store.OrganizationStore.
//
// The order is the slug and then the identifier, so a page is stable while
// rows arrive and leave.
func (s *Store) ListOrganizations(ctx context.Context, f store.OrganizationFilter) ([]store.Organization, string, error) {
	limit := pageSize(f.Limit)
	table := s.on.Organizations
	var where []string
	var args []any
	if f.UserID != "" {
		where = append(where, "id IN (SELECT org_id FROM "+s.on.Members+" WHERE user_id = ?)")
		args = append(args, f.UserID)
	}
	if f.Cursor != "" {
		slug, id, err := decodePairCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		where = append(where, "(slug > ? OR (slug = ? AND id > ?))")
		args = append(args, slug, slug, id)
	}
	query := "SELECT " + s.orgColumnList() + " FROM " + table
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY slug, id LIMIT ?"
	// One more row reports whether a page follows.
	args = append(args, limit+1)

	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, "", s.mapErr(err)
	}
	defer rows.Close()
	var out []store.Organization
	for rows.Next() {
		var o store.Organization
		extra := make([]any, len(s.orgFields))
		if err := rows.Scan(s.scanOrgRow(&o, extra)...); err != nil {
			return nil, "", s.mapErr(err)
		}
		s.collectOrgExtra(&o, extra)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, "", s.mapErr(err)
	}
	if len(out) > limit {
		last := out[limit-1]
		return out[:limit], encodePairCursor(last.Slug, last.ID), nil
	}
	return out, "", nil
}

// memberColumns are the columns of one membership row.
const memberColumns = "id, org_id, user_id, role, status, joined_at"

func scanMember(m *store.Membership) []any {
	return []any{&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.Status, timeScan{&m.JoinedAt}}
}

// CreateMembership implements store.MembershipStore.
func (s *Store) CreateMembership(ctx context.Context, m *store.Membership) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.on.Members+" ("+memberColumns+") VALUES (?, ?, ?, ?, ?, ?)",
		m.ID, m.OrgID, m.UserID, m.Role, m.Status, s.bindTime(m.JoinedAt))
	return s.mapErr(err)
}

// MembershipOf implements store.MembershipStore.
func (s *Store) MembershipOf(ctx context.Context, orgID, userID string) (*store.Membership, error) {
	row := s.queryRow(ctx,
		"SELECT "+memberColumns+" FROM "+s.on.Members+" WHERE org_id = ? AND user_id = ?", orgID, userID)
	var m store.Membership
	if err := row.Scan(scanMember(&m)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &m, nil
}

// UpdateMembership implements store.MembershipStore.
func (s *Store) UpdateMembership(ctx context.Context, m *store.Membership) error {
	result, err := s.exec(ctx,
		"UPDATE "+s.on.Members+" SET role = ?, status = ? WHERE org_id = ? AND user_id = ?",
		m.Role, m.Status, m.OrgID, m.UserID)
	if err != nil {
		return s.mapErr(err)
	}
	return notFoundWhenNoRow(result)
}

// DeleteMembership implements store.MembershipStore.
func (s *Store) DeleteMembership(ctx context.Context, orgID, userID string) error {
	result, err := s.exec(ctx,
		"DELETE FROM "+s.on.Members+" WHERE org_id = ? AND user_id = ?", orgID, userID)
	if err != nil {
		return s.mapErr(err)
	}
	return notFoundWhenNoRow(result)
}

// ListMembers implements store.MembershipStore.
//
// The order is the user identifier, which is unique inside one organization.
func (s *Store) ListMembers(ctx context.Context, f store.MemberFilter) ([]store.Membership, string, error) {
	limit := pageSize(f.Limit)
	where := []string{"org_id = ?"}
	args := []any{f.OrgID}
	if f.Role != nil {
		where = append(where, "role = ?")
		args = append(args, *f.Role)
	}
	if f.Status != nil {
		where = append(where, "status = ?")
		args = append(args, *f.Status)
	}
	if f.Cursor != "" {
		userID, err := decodeSingleCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		where = append(where, "user_id > ?")
		args = append(args, userID)
	}
	query := "SELECT " + memberColumns + " FROM " + s.on.Members +
		" WHERE " + strings.Join(where, " AND ") + " ORDER BY user_id LIMIT ?"
	args = append(args, limit+1)

	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, "", s.mapErr(err)
	}
	defer rows.Close()
	var out []store.Membership
	for rows.Next() {
		var m store.Membership
		if err := rows.Scan(scanMember(&m)...); err != nil {
			return nil, "", s.mapErr(err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, "", s.mapErr(err)
	}
	if len(out) > limit {
		return out[:limit], encodeSingleCursor(out[limit-1].UserID), nil
	}
	return out, "", nil
}

// MembershipsOfUser implements store.MembershipStore.
func (s *Store) MembershipsOfUser(ctx context.Context, userID string) ([]store.Membership, error) {
	rows, err := s.query(ctx,
		"SELECT "+memberColumns+" FROM "+s.on.Members+" WHERE user_id = ? ORDER BY org_id", userID)
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []store.Membership
	for rows.Next() {
		var m store.Membership
		if err := rows.Scan(scanMember(&m)...); err != nil {
			return nil, s.mapErr(err)
		}
		out = append(out, m)
	}
	return out, s.mapErr(rows.Err())
}

// LockActiveMembersWithRole implements store.MembershipStore.
func (s *Store) LockActiveMembersWithRole(ctx context.Context, orgID, role string) ([]string, error) {
	query := "SELECT user_id FROM " + s.on.Members + " WHERE org_id = ? AND role = ? AND status = ?"
	if s.d.Name == schema.Postgres {
		// The row lock ends with the transaction, so it is safe behind a
		// transaction pooler. SQLite needs no clause, because it serializes
		// the writers of one database.
		query += " FOR UPDATE"
	}
	rows, err := s.query(ctx, query, orgID, role, store.MembershipActive)
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, s.mapErr(err)
		}
		out = append(out, id)
	}
	return out, s.mapErr(rows.Err())
}

// CountMembers implements store.MembershipStore.
func (s *Store) CountMembers(ctx context.Context, orgID string) (int, error) {
	row := s.queryRow(ctx,
		"SELECT COUNT(*) FROM "+s.on.Members+" WHERE org_id = ? AND status = ?", orgID, store.MembershipActive)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, s.mapErr(err)
	}
	return count, nil
}

// pageSize bounds a requested page size.
func pageSize(limit int) int {
	if limit < 1 {
		return defaultOrgPage
	}
	if limit > maxOrgPage {
		return maxOrgPage
	}
	return limit
}

// notFoundWhenNoRow turns an update that changed no row into ErrNotFound.
func notFoundWhenNoRow(result interface{ RowsAffected() (int64, error) }) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return store.ErrNotFound
	}
	return nil
}

// encodePairCursor returns the opaque cursor of a two-column order.
func encodePairCursor(first, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(first + "\x00" + id))
}

// decodePairCursor returns the row that a two-column cursor names.
func decodePairCursor(value string) (string, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", "", store.ErrInvalidCursor
	}
	first, id, ok := strings.Cut(string(raw), "\x00")
	if !ok {
		return "", "", store.ErrInvalidCursor
	}
	return first, id, nil
}

// encodeSingleCursor returns the opaque cursor of a one-column order.
func encodeSingleCursor(id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(id))
}

// decodeSingleCursor returns the row that a one-column cursor names.
func decodeSingleCursor(value string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", store.ErrInvalidCursor
	}
	return string(raw), nil
}
