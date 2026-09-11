package authall_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	authall "github.com/alternayte/auth-all"
	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/internal/testsupport"
	"github.com/alternayte/auth-all/plugins/organizations"
	"github.com/alternayte/auth-all/store"
)

// inviteBody is the decoded body of one invitation response.
type inviteBody struct {
	Invitation struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		Status    string `json:"status"`
		ExpiresAt string `json:"expiresAt"`
	} `json:"invitation"`
	Token string `json:"token"`
}

// invite creates one invitation through the HTTP route.
func invite(t *testing.T, h *testsupport.Harness, orgID, address, role string) inviteBody {
	t.Helper()
	resp := h.Do(http.MethodPost, "/organizations/"+orgID+"/invitations",
		map[string]any{"email": address, "role": role})
	if resp.Status != http.StatusCreated {
		t.Fatalf("invite %s: %d %s", address, resp.Status, string(resp.Body))
	}
	var body inviteBody
	resp.Decode(t, &body)
	return body
}

// TestSCNINV001TheTokenAppearsOneTime proves SCN-INV-001, REQ-INV-001,
// REQ-INV-002, REQ-INV-003, and SI-06.
func TestSCNINV001TheTokenAppearsOneTime(t *testing.T) {
	h, _ := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)

	body := invite(t, h, orgID, "new@example.com", "admin")
	if body.Token == "" {
		t.Fatal("the response holds no token")
	}
	if body.Invitation.Email != "new@example.com" || body.Invitation.Role != "admin" {
		t.Fatalf("the invitation = %+v", body.Invitation)
	}
	if body.Invitation.Status != store.InvitationPending {
		t.Fatalf("the status = %q, want pending", body.Invitation.Status)
	}

	// The store holds the digest of 64 hexadecimal characters, never the
	// plaintext.
	invitations := h.Store.(store.InvitationStore)
	stored, err := invitations.InvitationByTokenHash(context.Background(), sha256Hex(body.Token))
	if err != nil {
		t.Fatalf("read the invitation by digest: %v", err)
	}
	if len(stored.TokenHash) != 64 {
		t.Fatalf("the digest has %d characters, want 64", len(stored.TokenHash))
	}
	if stored.TokenHash == body.Token {
		t.Fatal("the store holds the plaintext token")
	}

	// The list route never carries the token or the digest.
	list := h.Do(http.MethodGet, "/organizations/"+orgID+"/invitations", nil)
	if list.Status != http.StatusOK {
		t.Fatalf("the list got status %d: %s", list.Status, string(list.Body))
	}
	page := string(list.Body)
	for _, secret := range []string{body.Token, stored.TokenHash} {
		if secret != "" && strings.Contains(page, secret) {
			t.Fatal("the list carries the invitation secret")
		}
	}
}

// TestSCNINV002AnInvitationNeverNamesAHigherRole proves SCN-INV-002 and
// REQ-INV-005.
func TestSCNINV002AnInvitationNeverNamesAHigherRole(t *testing.T) {
	h, _ := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	addMember(t, h, orgID, "admin@example.com", "admin")

	signInAs(t, h, "admin@example.com")
	activate(t, h, orgID)
	resp := h.Do(http.MethodPost, "/organizations/"+orgID+"/invitations",
		map[string]any{"email": "new@example.com", "role": "owner"})
	if resp.Status != http.StatusForbidden {
		t.Fatalf("status %d, want 403: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != string(apierr.CodeRoleNotAllowed) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeRoleNotAllowed)
	}

	// The admin invites a role that the admin holds.
	if body := invite(t, h, orgID, "new@example.com", "member"); body.Token == "" {
		t.Fatal("the allowed invitation returned no token")
	}
}

// TestSCNINV003OnlyTheNamedAddressAccepts proves SCN-INV-003, REQ-INV-006, and
// SI-07.
func TestSCNINV003OnlyTheNamedAddressAccepts(t *testing.T) {
	h, _ := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)
	body := invite(t, h, orgID, "invited@example.com", "member")

	// Another signed-in user cannot accept it.
	h.ClearCookies()
	h.SignUp("mallory@example.com", testPassword)
	refused := h.Do(http.MethodPost, "/organizations/invitations/accept",
		map[string]any{"token": body.Token})
	if refused.Status != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", refused.Status, string(refused.Body))
	}
	if code := refused.ErrorCode(t); code != string(apierr.CodeInvitationInvalid) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeInvitationInvalid)
	}

	// The invitation is still pending after the wrong attempt.
	invitations := h.Store.(store.InvitationStore)
	stored, err := invitations.InvitationByTokenHash(context.Background(), sha256Hex(body.Token))
	if err != nil {
		t.Fatalf("read the invitation: %v", err)
	}
	if stored.Status != store.InvitationPending {
		t.Fatalf("a wrong address spent the invitation: %q", stored.Status)
	}

	// The named address accepts it.
	h.ClearCookies()
	_, out := h.SignUp("invited@example.com", testPassword)
	accepted := h.Do(http.MethodPost, "/organizations/invitations/accept",
		map[string]any{"token": body.Token})
	if accepted.Status != http.StatusOK {
		t.Fatalf("the acceptance got status %d: %s", accepted.Status, string(accepted.Body))
	}
	var member membershipBody
	accepted.Decode(t, &member)
	if member.Membership.Role != "member" {
		t.Fatalf("the role = %q, want member", member.Membership.Role)
	}
	if got := membershipOf(t, h.Store, orgID, out.User.ID); got.Role != "member" {
		t.Fatalf("the stored membership = %+v", got)
	}
}

// TestSCNINV004TheInvalidCasesLookEqual proves SCN-INV-004, REQ-INV-007, and
// REQ-INV-010. An accepted, a revoked, and an expired invitation give one body.
func TestSCNINV004TheInvalidCasesLookEqual(t *testing.T) {
	clock := testsupport.NewClock()
	orgs := organizations.New(testRoles(),
		organizations.DefaultRole("member"), organizations.OwnerRole("owner"))
	h := testsupport.NewHarness(t, authall.WithEmailPassword(),
		authall.WithPlugins(orgs), authall.WithClock(clock.Now))
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)

	accepted := invite(t, h, orgID, "accepted@example.com", "member")
	revoked := invite(t, h, orgID, "revoked@example.com", "member")
	expired := invite(t, h, orgID, "expired@example.com", "member")

	// One invitation is accepted.
	jar := h.SaveCookies()
	h.ClearCookies()
	h.SignUp("accepted@example.com", testPassword)
	if resp := h.Do(http.MethodPost, "/organizations/invitations/accept",
		map[string]any{"token": accepted.Token}); resp.Status != http.StatusOK {
		t.Fatalf("the first acceptance got status %d: %s", resp.Status, string(resp.Body))
	}
	h.RestoreCookies(jar)

	// One invitation is revoked.
	revoke := h.Do(http.MethodPost,
		"/organizations/"+orgID+"/invitations/"+revoked.Invitation.ID+"/revoke", nil)
	if revoke.Status != http.StatusOK {
		t.Fatalf("the revocation got status %d: %s", revoke.Status, string(revoke.Body))
	}

	// One invitation expires.
	clock.Advance(organizations.DefaultInvitationTTL + time.Minute)

	bodies := map[string]string{}
	for name, tc := range map[string]struct {
		address string
		token   string
	}{
		"accepted": {"accepted@example.com", accepted.Token},
		"revoked":  {"revoked@example.com", revoked.Token},
		"expired":  {"expired@example.com", expired.Token},
		"unknown":  {"expired@example.com", "a-token-that-never-existed"},
	} {
		h.ClearCookies()
		if _, out := h.SignIn(tc.address, testPassword); out.User == nil {
			h.SignUp(tc.address, testPassword)
		}
		resp := h.Do(http.MethodPost, "/organizations/invitations/accept",
			map[string]any{"token": tc.token})
		if resp.Status != http.StatusBadRequest {
			t.Fatalf("the %s invitation got status %d: %s", name, resp.Status, string(resp.Body))
		}
		bodies[name] = string(resp.Body)
	}
	first := bodies["accepted"]
	for name, body := range bodies {
		if body != first {
			t.Fatalf("the %s invitation gives another body:\n%s\n%s", name, body, first)
		}
	}
}

// TestSCNINV006AMemberNeedsNoInvitation proves SCN-INV-006 and REQ-INV-009.
func TestSCNINV006AMemberNeedsNoInvitation(t *testing.T) {
	h, _ := activeHarness(t)
	orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
	addMember(t, h, orgID, "bob@example.com", "member")
	activate(t, h, orgID)

	resp := h.Do(http.MethodPost, "/organizations/"+orgID+"/invitations",
		map[string]any{"email": "bob@example.com", "role": "admin"})
	if resp.Status != http.StatusConflict {
		t.Fatalf("status %d, want 409: %s", resp.Status, string(resp.Body))
	}
	if code := resp.ErrorCode(t); code != string(apierr.CodeAlreadyMember) {
		t.Fatalf("the code = %s, want %s", code, apierr.CodeAlreadyMember)
	}
}

// TestSCNINV007TheInvitationEmitsTheIntent proves SCN-INV-007, REQ-INV-011,
// and SI-11. Auth-All sends no message, and no event carries the token.
func TestSCNINV007TheInvitationEmitsTheIntent(t *testing.T) {
	var seen []events.Event
	orgs := organizations.New(testRoles(),
		organizations.DefaultRole("member"), organizations.OwnerRole("owner"))
	h := testsupport.NewHarness(t, authall.WithEmailPassword(), authall.WithPlugins(orgs),
		authall.WithEventHandler(events.HandlerFunc(func(_ context.Context, e events.Event) {
			seen = append(seen, e)
		})))
	orgID, owner := newOrganization(t, h, "owner@example.com", "acme")
	activate(t, h, orgID)

	before := h.Mail.Count()
	body := invite(t, h, orgID, "new@example.com", "member")

	// Auth-All sends no message. The application sends the invitation.
	if h.Mail.Count() != before {
		t.Fatalf("Auth-All sent %d messages", h.Mail.Count()-before)
	}

	var event *events.Event
	for i := range seen {
		if seen[i].Name == events.InvitationCreated {
			event = &seen[i]
		}
	}
	if event == nil {
		t.Fatal("no invitation event was emitted")
	}
	if got := event.Fields["email"]; got != "new@example.com" {
		t.Fatalf("the event address = %v", got)
	}
	if got := event.Fields["orgId"]; got != orgID {
		t.Fatalf("the event organization = %v, want %s", got, orgID)
	}
	if got := event.Fields["role"]; got != "member" {
		t.Fatalf("the event role = %v", got)
	}
	if event.Fields["invitationId"] != body.Invitation.ID {
		t.Fatalf("the event names another invitation: %v", event.Fields["invitationId"])
	}
	if event.UserID != owner {
		t.Fatalf("the event actor = %q, want the inviter", event.UserID)
	}
	// No event carries the token or the digest.
	for _, e := range seen {
		for name, value := range e.Fields {
			text, ok := value.(string)
			if !ok {
				continue
			}
			if text == body.Token || text == sha256Hex(body.Token) {
				t.Fatalf("the event %s carries the invitation secret in %s", e.Name, name)
			}
		}
	}
}

// TestSCNINV008TheExpiryIsSevenDaysAndConfigurable proves SCN-INV-008 and
// REQ-INV-004.
func TestSCNINV008TheExpiryIsSevenDaysAndConfigurable(t *testing.T) {
	if organizations.DefaultInvitationTTL != 7*24*time.Hour {
		t.Fatalf("the default expiry = %v, want 7 days", organizations.DefaultInvitationTTL)
	}
	now := time.Now().UTC().Truncate(time.Second)

	for _, tc := range []struct {
		name string
		opts []organizations.Option
		want time.Duration
	}{
		{"the default expiry", nil, organizations.DefaultInvitationTTL},
		{"the configured expiry", []organizations.Option{organizations.InvitationTTL(48 * time.Hour)}, 48 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := testsupport.NewClockAt(now)
			all := append([]organizations.Option{testRoles(),
				organizations.DefaultRole("member"), organizations.OwnerRole("owner")}, tc.opts...)
			orgs := organizations.New(all...)
			h := testsupport.NewHarness(t, authall.WithEmailPassword(),
				authall.WithPlugins(orgs), authall.WithClock(clock.Now))
			orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
			activate(t, h, orgID)
			body := invite(t, h, orgID, "new@example.com", "member")

			invitations := h.Store.(store.InvitationStore)
			stored, err := invitations.InvitationByTokenHash(context.Background(), sha256Hex(body.Token))
			if err != nil {
				t.Fatalf("read the invitation: %v", err)
			}
			if got := stored.ExpiresAt.Sub(stored.CreatedAt); got != tc.want {
				t.Fatalf("the expiry = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSCNMEM010TheMemberLimitCountsThePendingInvitations proves SCN-MEM-010
// and REQ-MEM-011. The count holds the active members and the pending
// invitations, and it runs inside the write transaction. The scenario runs on
// both engines.
func TestSCNMEM010TheMemberLimitCountsThePendingInvitations(t *testing.T) {
	engines := map[string]func(t *testing.T) store.Store{
		"SQLite":     testsupport.NewSQLite,
		"PostgreSQL": testsupport.NewPostgres,
	}
	for name, newStore := range engines {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			orgs := organizations.New(testRoles(), organizations.DefaultRole("member"),
				organizations.OwnerRole("owner"), organizations.MaxMembers(3))
			h := testsupport.NewHarnessWithStore(t, s,
				authall.WithEmailPassword(), authall.WithPlugins(orgs))

			// The organization holds two members and one pending invitation.
			orgID, _ := newOrganization(t, h, "owner@example.com", "acme")
			addMember(t, h, orgID, "second@example.com", "member")
			activate(t, h, orgID)
			invite(t, h, orgID, "third@example.com", "member")

			// The limit of 3 refuses the next invitation.
			refused := h.Do(http.MethodPost, "/organizations/"+orgID+"/invitations",
				map[string]any{"email": "fourth@example.com", "role": "member"})
			if refused.Status != http.StatusConflict {
				t.Fatalf("status %d, want 409: %s", refused.Status, string(refused.Body))
			}
			if code := refused.ErrorCode(t); code != string(apierr.CodeMemberLimit) {
				t.Fatalf("the code = %s, want %s", code, apierr.CodeMemberLimit)
			}

			// A revoked invitation frees the place again.
			list := h.Do(http.MethodGet, "/organizations/"+orgID+"/invitations", nil)
			var page struct {
				Invitations []struct {
					ID string `json:"id"`
				} `json:"invitations"`
			}
			list.Decode(t, &page)
			if len(page.Invitations) != 1 {
				t.Fatalf("the organization holds %d invitations, want 1", len(page.Invitations))
			}
			revoke := h.Do(http.MethodPost,
				"/organizations/"+orgID+"/invitations/"+page.Invitations[0].ID+"/revoke", nil)
			if revoke.Status != http.StatusOK {
				t.Fatalf("the revocation got status %d: %s", revoke.Status, string(revoke.Body))
			}
			allowed := h.Do(http.MethodPost, "/organizations/"+orgID+"/invitations",
				map[string]any{"email": "fourth@example.com", "role": "member"})
			if allowed.Status != http.StatusCreated {
				t.Fatalf("the invitation after the revocation got status %d: %s",
					allowed.Status, string(allowed.Body))
			}
		})
	}
}
