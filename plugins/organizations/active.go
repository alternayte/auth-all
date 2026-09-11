package organizations

import (
	"context"
	"errors"
	"net/http"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/plugin"
	"github.com/alternayte/auth-all/store"
)

// SetActive writes the active organization in the session row of the caller.
//
// The active organization lives in the session, so every instance reads it,
// and a revocation removes it with the session. A request value never sets it.
// SetActive fails when the caller holds no active membership there.
func (p *Plugin) SetActive(ctx context.Context, w http.ResponseWriter, r *http.Request, orgID string) error {
	principal := p.principals.Current(r.Context())
	if principal == nil {
		return apierr.ErrUnauthorized
	}
	if principal.Session == nil {
		// A key names its organization at creation, so a key never switches.
		return apierr.ErrForbidden.WithMessage("Only a session can switch the organization.")
	}
	return p.setActiveSession(ctx, principal, orgID)
}

// setActiveSession writes the organization of one session.
func (p *Plugin) setActiveSession(ctx context.Context, principal *plugin.Principal, orgID string) error {
	sessions, ok := p.store.(store.ActiveOrganizationStore)
	if !ok {
		return errors.New("authall/organizations: the configured store holds no active organization")
	}
	if orgID == "" {
		return sessions.SetActiveOrganization(ctx, principal.Session.ID, "")
	}
	if _, err := p.orgs.OrganizationByID(ctx, orgID); err != nil {
		return notFound(err)
	}
	m, err := p.membershipOf(ctx, orgID, principal.User.ID)
	if err != nil {
		return err
	}
	if m.Status != store.MembershipActive {
		return apierr.ErrNotAMember
	}
	if err := sessions.SetActiveOrganization(ctx, principal.Session.ID, orgID); err != nil {
		return err
	}
	p.emit(ctx, events.ActiveOrganizationSet, principal.User.ID, orgID, nil)
	return nil
}

// registerActiveRoutes mounts the switch route.
func (p *Plugin) registerActiveRoutes(r *plugin.Registry) {
	tag := []string{"organizations"}
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations/{id}/activate", Handler: p.guard(p.handleActivate),
		Operation: orgOperation("setActiveOrganization", "Switch the active organization", tag, nil,
			openapi.Ref("SuccessResponse"), "setActive", "404"),
	})
	r.Route(plugin.Route{
		Method: http.MethodPost, Path: "/organizations/deactivate", Handler: p.guard(p.handleDeactivate),
		Operation: operation("clearActiveOrganization", "End the active organization", tag, nil,
			openapi.Ref("SuccessResponse"), "clearActive"),
	})
}

// handleActivate serves POST /organizations/{id}/activate.
//
// The organization comes from the path of this route only. No header and no
// query parameter of another route changes the active organization.
func (p *Plugin) handleActivate(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	if principal.Session == nil {
		p.writeErr(w, r, apierr.ErrForbidden.WithMessage("Only a session can switch the organization."))
		return
	}
	if err := p.setActiveSession(r.Context(), principal, r.PathValue("id")); err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// handleDeactivate serves POST /organizations/deactivate.
func (p *Plugin) handleDeactivate(w http.ResponseWriter, r *http.Request, principal *plugin.Principal) {
	if principal.Session == nil {
		p.writeErr(w, r, apierr.ErrForbidden.WithMessage("Only a session can switch the organization."))
		return
	}
	if err := p.setActiveSession(r.Context(), principal, ""); err != nil {
		p.writeErr(w, r, err)
		return
	}
	p.svc.HTTP().WriteJSON(w, http.StatusOK, map[string]bool{"success": true})
}
