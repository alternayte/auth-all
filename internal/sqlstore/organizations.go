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

// SetActiveOrganization implements store.ActiveOrganizationStore.
func (s *Store) SetActiveOrganization(ctx context.Context, sessionID, orgID string) error {
	var value any
	if orgID != "" {
		value = orgID
	}
	result, err := s.exec(ctx,
		"UPDATE "+s.n.Sessions+" SET active_org_id = ? WHERE id = ?", value, sessionID)
	if err != nil {
		return s.mapErr(err)
	}
	return notFoundWhenNoRow(result)
}

// ActiveOrganizationOf implements store.ActiveOrganizationStore.
func (s *Store) ActiveOrganizationOf(ctx context.Context, sessionID string) (string, error) {
	row := s.queryRow(ctx, "SELECT active_org_id FROM "+s.n.Sessions+" WHERE id = ?", sessionID)
	var orgID *string
	if err := row.Scan(nullStringScan{&orgID}); err != nil {
		return "", s.mapErr(err)
	}
	if orgID == nil {
		return "", nil
	}
	return *orgID, nil
}

// ClearActiveOrganization implements store.ActiveOrganizationStore.
func (s *Store) ClearActiveOrganization(ctx context.Context, orgID, userID string) error {
	_, err := s.exec(ctx,
		"UPDATE "+s.n.Sessions+" SET active_org_id = NULL WHERE user_id = ? AND active_org_id = ?",
		userID, orgID)
	return s.mapErr(err)
}

// SessionWithUserAndMembership implements store.SessionOrgReader.
//
// One statement returns the session row, the user row, the organization row,
// and the membership row. A permission check therefore costs no extra round
// trip. The joins are left joins, so a session with no active organization
// returns the same row shape.
func (s *Store) SessionWithUserAndMembership(ctx context.Context, tokenHash string) (
	*store.Session, *store.User, *store.Organization, *store.Membership, error) {
	sessionCols := prefixColumns("s", sessionColumns)
	userCols := prefixColumns("u", s.userColumnList())
	orgCols := prefixColumns("o", s.orgColumnList())
	memberCols := prefixColumns("m", memberColumns)
	query := "SELECT " + sessionCols + ", " + userCols + ", " + orgCols + ", " + memberCols +
		", r.permissions" +
		" FROM " + s.n.Sessions + " s" +
		" JOIN " + s.n.Users + " u ON u.id = s.user_id" +
		" LEFT JOIN " + s.on.Organizations + " o ON o.id = s.active_org_id" +
		" LEFT JOIN " + s.on.Members + " m ON m.org_id = s.active_org_id AND m.user_id = s.user_id" +
		// A custom role of the organization carries its own statements, so the
		// same statement resolves them with no extra round trip.
		" LEFT JOIN " + s.on.Roles + " r ON r.org_id = m.org_id AND r.name = m.role" +
		" WHERE s.token_hash = ?"

	var sess store.Session
	var user store.User
	// The left joins can return null in every column of the organization and
	// of the membership, so the scan reads them into nullable holders.
	var org nullableOrganization
	var member nullableMembership
	targets := []any{&sess.ID, &sess.UserID, &sess.TokenHash,
		timeScan{&sess.CreatedAt}, timeScan{&sess.ExpiresAt}, timeScan{&sess.LastSeenAt}}
	extra := make([]any, len(s.fields))
	targets = append(targets, s.scanUserRow(&user, extra)...)
	orgExtra := make([]any, len(s.orgFields))
	targets = append(targets, org.targets(len(s.orgFields), orgExtra)...)
	targets = append(targets, member.targets()...)
	var permissions *string
	targets = append(targets, nullStringScan{&permissions})

	if err := s.queryRow(ctx, query, tokenHash).Scan(targets...); err != nil {
		return nil, nil, nil, nil, s.mapErr(err)
	}
	s.collectExtra(&user, extra)
	out := org.value()
	if out != nil {
		s.collectOrgExtra(out, orgExtra)
	}
	resolved := member.value()
	if resolved != nil && permissions != nil {
		resolved.Permissions = *permissions
	}
	return &sess, &user, out, resolved, nil
}

// nullableOrganization scans the organization columns of a left join.
type nullableOrganization struct {
	id        *string
	name      *string
	slug      *string
	createdAt *time.Time
	updatedAt *time.Time
}

func (n *nullableOrganization) targets(fields int, extra []any) []any {
	out := []any{nullStringScan{&n.id}, nullStringScan{&n.name}, nullStringScan{&n.slug},
		nullTimeScan{&n.createdAt}, nullTimeScan{&n.updatedAt}}
	for i := range fields {
		out = append(out, &extra[i])
	}
	return out
}

func (n *nullableOrganization) value() *store.Organization {
	if n.id == nil {
		return nil
	}
	out := &store.Organization{ID: *n.id}
	if n.name != nil {
		out.Name = *n.name
	}
	if n.slug != nil {
		out.Slug = *n.slug
	}
	if n.createdAt != nil {
		out.CreatedAt = *n.createdAt
	}
	if n.updatedAt != nil {
		out.UpdatedAt = *n.updatedAt
	}
	return out
}

// nullableMembership scans the membership columns of a left join.
type nullableMembership struct {
	id       *string
	orgID    *string
	userID   *string
	role     *string
	status   *string
	joinedAt *time.Time
}

func (n *nullableMembership) targets() []any {
	return []any{nullStringScan{&n.id}, nullStringScan{&n.orgID}, nullStringScan{&n.userID},
		nullStringScan{&n.role}, nullStringScan{&n.status}, nullTimeScan{&n.joinedAt}}
}

func (n *nullableMembership) value() *store.Membership {
	if n.id == nil {
		return nil
	}
	out := &store.Membership{ID: *n.id}
	if n.orgID != nil {
		out.OrgID = *n.orgID
	}
	if n.userID != nil {
		out.UserID = *n.userID
	}
	if n.role != nil {
		out.Role = *n.role
	}
	if n.status != nil {
		out.Status = *n.status
	}
	if n.joinedAt != nil {
		out.JoinedAt = *n.joinedAt
	}
	return out
}

// invitationColumns are the columns of one invitation row.
const invitationColumns = "id, org_id, email_normalized, role, invited_by, token_hash, status, expires_at, created_at"

func scanInvitation(i *store.Invitation) []any {
	return []any{&i.ID, &i.OrgID, &i.EmailNormalized, &i.Role, &i.InvitedBy,
		&i.TokenHash, &i.Status, timeScan{&i.ExpiresAt}, timeScan{&i.CreatedAt}}
}

// CreateInvitation implements store.InvitationStore.
func (s *Store) CreateInvitation(ctx context.Context, i *store.Invitation) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.on.Invitations+" ("+invitationColumns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		i.ID, i.OrgID, i.EmailNormalized, i.Role, i.InvitedBy, i.TokenHash, i.Status,
		s.bindTime(i.ExpiresAt), s.bindTime(i.CreatedAt))
	return s.mapErr(err)
}

// InvitationByTokenHash implements store.InvitationStore.
func (s *Store) InvitationByTokenHash(ctx context.Context, tokenHash string) (*store.Invitation, error) {
	return s.invitation(ctx, "token_hash = ?", tokenHash)
}

// InvitationByID implements store.InvitationStore.
func (s *Store) InvitationByID(ctx context.Context, id string) (*store.Invitation, error) {
	return s.invitation(ctx, "id = ?", id)
}

func (s *Store) invitation(ctx context.Context, where string, arg any) (*store.Invitation, error) {
	row := s.queryRow(ctx, "SELECT "+invitationColumns+" FROM "+s.on.Invitations+" WHERE "+where, arg)
	var i store.Invitation
	if err := row.Scan(scanInvitation(&i)...); err != nil {
		return nil, s.mapErr(err)
	}
	return &i, nil
}

// ConsumeInvitation implements store.InvitationStore.
//
// One conditional update changes the status, so two parallel acceptances of
// one invitation never both pass.
func (s *Store) ConsumeInvitation(ctx context.Context, tokenHash string, now time.Time) (*store.Invitation, error) {
	result, err := s.exec(ctx,
		"UPDATE "+s.on.Invitations+" SET status = ? WHERE token_hash = ? AND status = ? AND expires_at > ?",
		store.InvitationAccepted, tokenHash, store.InvitationPending, s.bindTime(now))
	if err != nil {
		return nil, s.mapErr(err)
	}
	if err := notFoundWhenNoRow(result); err != nil {
		return nil, err
	}
	return s.InvitationByTokenHash(ctx, tokenHash)
}

// SetInvitationStatus implements store.InvitationStore.
func (s *Store) SetInvitationStatus(ctx context.Context, id, from, to string) error {
	result, err := s.exec(ctx,
		"UPDATE "+s.on.Invitations+" SET status = ? WHERE id = ? AND status = ?", to, id, from)
	if err != nil {
		return s.mapErr(err)
	}
	return notFoundWhenNoRow(result)
}

// ListInvitations implements store.InvitationStore.
func (s *Store) ListInvitations(ctx context.Context, f store.InvitationFilter) ([]store.Invitation, string, error) {
	limit := pageSize(f.Limit)
	where := []string{"org_id = ?"}
	args := []any{f.OrgID}
	if f.Status != nil {
		where = append(where, "status = ?")
		args = append(args, *f.Status)
	}
	if f.Cursor != "" {
		id, err := decodeSingleCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		where = append(where, "id > ?")
		args = append(args, id)
	}
	query := "SELECT " + invitationColumns + " FROM " + s.on.Invitations +
		" WHERE " + strings.Join(where, " AND ") + " ORDER BY id LIMIT ?"
	args = append(args, limit+1)

	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return nil, "", s.mapErr(err)
	}
	defer rows.Close()
	var out []store.Invitation
	for rows.Next() {
		var i store.Invitation
		if err := rows.Scan(scanInvitation(&i)...); err != nil {
			return nil, "", s.mapErr(err)
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		return nil, "", s.mapErr(err)
	}
	if len(out) > limit {
		return out[:limit], encodeSingleCursor(out[limit-1].ID), nil
	}
	return out, "", nil
}

// CountPendingInvitations implements store.InvitationStore.
func (s *Store) CountPendingInvitations(ctx context.Context, orgID string, now time.Time) (int, error) {
	row := s.queryRow(ctx,
		"SELECT COUNT(*) FROM "+s.on.Invitations+" WHERE org_id = ? AND status = ? AND expires_at > ?",
		orgID, store.InvitationPending, s.bindTime(now))
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, s.mapErr(err)
	}
	return count, nil
}

// customRoleColumns are the columns of one custom role row.
const customRoleColumns = "id, org_id, name, permissions, created_at"

// CreateCustomRole implements store.CustomRoleStore.
func (s *Store) CreateCustomRole(ctx context.Context, r *store.CustomRole) error {
	_, err := s.exec(ctx,
		"INSERT INTO "+s.on.Roles+" ("+customRoleColumns+") VALUES (?, ?, ?, ?, ?)",
		r.ID, r.OrgID, r.Name, r.Permissions, s.bindTime(r.CreatedAt))
	return s.mapErr(err)
}

// CustomRoleByName implements store.CustomRoleStore.
func (s *Store) CustomRoleByName(ctx context.Context, orgID, name string) (*store.CustomRole, error) {
	row := s.queryRow(ctx,
		"SELECT "+customRoleColumns+" FROM "+s.on.Roles+" WHERE org_id = ? AND name = ?", orgID, name)
	var r store.CustomRole
	if err := row.Scan(&r.ID, &r.OrgID, &r.Name, &r.Permissions, timeScan{&r.CreatedAt}); err != nil {
		return nil, s.mapErr(err)
	}
	return &r, nil
}

// ListCustomRoles implements store.CustomRoleStore.
func (s *Store) ListCustomRoles(ctx context.Context, orgID string) ([]store.CustomRole, error) {
	rows, err := s.query(ctx,
		"SELECT "+customRoleColumns+" FROM "+s.on.Roles+" WHERE org_id = ? ORDER BY name", orgID)
	if err != nil {
		return nil, s.mapErr(err)
	}
	defer rows.Close()
	var out []store.CustomRole
	for rows.Next() {
		var r store.CustomRole
		if err := rows.Scan(&r.ID, &r.OrgID, &r.Name, &r.Permissions, timeScan{&r.CreatedAt}); err != nil {
			return nil, s.mapErr(err)
		}
		out = append(out, r)
	}
	return out, s.mapErr(rows.Err())
}

// DeleteCustomRole implements store.CustomRoleStore.
func (s *Store) DeleteCustomRole(ctx context.Context, orgID, name string) error {
	result, err := s.exec(ctx, "DELETE FROM "+s.on.Roles+" WHERE org_id = ? AND name = ?", orgID, name)
	if err != nil {
		return s.mapErr(err)
	}
	return notFoundWhenNoRow(result)
}
