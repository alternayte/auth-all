package authall

import (
	"net/http"

	"github.com/alternayte/auth-all/apierr"
	"github.com/alternayte/auth-all/events"
	"github.com/alternayte/auth-all/hook"
	"github.com/alternayte/auth-all/openapi"
	"github.com/alternayte/auth-all/store"
)

// registerSessionRoutes mounts the session management endpoints.
func (a *Auth) registerSessionRoutes() {
	tag := []string{"session"}

	a.handle(http.MethodGet, "/sessions", a.handleListSessions, operation(
		"listSessions", "List the sessions of the current user", tag, nil,
		"The sessions of the current user", openapi.Ref("SessionListResponse"),
		&openapi.ClientBinding{Namespace: "sessions", Method: "list"}, "401"))

	a.handle(http.MethodDelete, "/sessions/{id}", a.handleRevokeSession, &openapi.Operation{
		OperationID: "revokeSession",
		Summary:     "Revoke one session of the current user",
		Description: "A session of another user answers with 404, so the endpoint " +
			"discloses nothing about the existence of that session.",
		Tags: tag,
		Parameters: []openapi.Parameter{
			{Name: "id", In: "path", Required: true, Schema: openapi.String()},
		},
		Responses: mergeResponses(
			map[string]openapi.Response{
				"200": openapi.JSONResponse("The session is revoked", openapi.Ref("SuccessResponse")),
			},
			errorResponses("401", "403", "404")),
		Client: &openapi.ClientBinding{Namespace: "sessions", Method: "revoke"},
	})

	a.handle(http.MethodPost, "/sessions/revoke-all", a.handleRevokeAllSessions, operation(
		"revokeAllSessions", "Revoke the other sessions of the current user", tag,
		openapi.JSONBody(openapi.Object(nil, map[string]*openapi.Schema{
			"includeCurrent": openapi.Bool(),
		})),
		"The number of revoked sessions", openapi.Ref("RevokeAllResponse"),
		&openapi.ClientBinding{Namespace: "sessions", Method: "revokeAll"}, "401", "403"))
}

// mergeResponses joins two response maps into one.
func mergeResponses(first, second map[string]openapi.Response) map[string]openapi.Response {
	out := map[string]openapi.Response{}
	for code, response := range first {
		out[code] = response
	}
	for code, response := range second {
		out[code] = response
	}
	return out
}

// requireSession resolves the session of a request. It writes the error and
// returns nil values when the request carries no valid session.
func (a *Auth) requireSession(w http.ResponseWriter, r *http.Request) (*store.Session, *store.User) {
	sess, user, err := a.resolveSession(r.Context(), r)
	if err != nil {
		a.writeError(w, err)
		return nil, nil
	}
	if sess == nil || user == nil {
		a.writeError(w, apierr.ErrUnauthorized)
		return nil, nil
	}
	return sess, user
}

func (a *Auth) handleListSessions(w http.ResponseWriter, r *http.Request) {
	sess, _ := a.requireSession(w, r)
	if sess == nil {
		return
	}
	list, err := a.cfg.store.Sessions().ListByUser(r.Context(), sess.UserID)
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	entries := make([]sessionEntryDTO, 0, len(list))
	for _, item := range list {
		entries = append(entries, toSessionEntryDTO(item))
	}
	a.writeJSON(w, http.StatusOK, sessionListResponse{Sessions: entries})
}

func (a *Auth) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, _ := a.requireSession(w, r)
	if sess == nil {
		return
	}
	id := r.PathValue("id")
	list, err := a.cfg.store.Sessions().ListByUser(ctx, sess.UserID)
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	// The list holds only the sessions of the current user, so a session of
	// another user cannot match. The endpoint therefore answers 404 for a
	// foreign session and for an unknown one, and it discloses nothing.
	owned := false
	for _, item := range list {
		if item.ID == id {
			owned = true
			break
		}
	}
	if !owned {
		a.writeError(w, apierr.ErrNotFound)
		return
	}
	if err := a.cfg.store.Sessions().Delete(ctx, id); err != nil && !isNotFound(err) {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	a.hooks.RunAfterSignOut(ctx, &hook.SignOut{UserID: sess.UserID, SessionID: id})
	a.emitter.Emit(ctx, events.SignOut, sess.UserID, map[string]any{"session_id": id})
	if id == sess.ID {
		a.clearCookie(w)
	}
	a.writeJSON(w, http.StatusOK, successResponse{Success: true})
}

type revokeAllRequest struct {
	// IncludeCurrent also revokes the session of this request. The default
	// keeps it, so the person stays signed in on this device.
	IncludeCurrent bool `json:"includeCurrent"`
}

func (a *Auth) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := a.checkOrigin(r); err != nil {
		a.writeError(w, err)
		return
	}
	sess, _ := a.requireSession(w, r)
	if sess == nil {
		return
	}
	var req revokeAllRequest
	if r.ContentLength != 0 {
		if err := a.decodeJSON(r, &req); err != nil {
			a.writeError(w, err)
			return
		}
	}
	list, err := a.cfg.store.Sessions().ListByUser(ctx, sess.UserID)
	if err != nil {
		a.writeError(w, apierr.ErrInternal.WithCause(err))
		return
	}
	revoked := 0
	for _, item := range list {
		if item.ID == sess.ID && !req.IncludeCurrent {
			continue
		}
		if err := a.cfg.store.Sessions().Delete(ctx, item.ID); err != nil && !isNotFound(err) {
			a.writeError(w, apierr.ErrInternal.WithCause(err))
			return
		}
		revoked++
		a.hooks.RunAfterSignOut(ctx, &hook.SignOut{UserID: sess.UserID, SessionID: item.ID})
	}
	a.emitter.Emit(ctx, events.SignOut, sess.UserID, map[string]any{"revoked": revoked})
	if req.IncludeCurrent {
		a.clearCookie(w)
	}
	a.writeJSON(w, http.StatusOK, revokeAllResponse{Revoked: revoked})
}
