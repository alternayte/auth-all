package hook

import (
	"context"

	"github.com/alternayte/auth-all/store"
)

// OrganizationEvent carries one organization change. A Before hook receives
// the transactional store, so the application writes its own rows in the same
// transaction.
type OrganizationEvent struct {
	// Org is the organization of the change.
	Org *store.Organization
	// Actor is the person who runs the change. It is nil for a change that no
	// person started.
	Actor *store.User
	// Tx is the transactional store of the running change.
	Tx store.Store
}

// MembershipEvent carries one membership change.
type MembershipEvent struct {
	// Org is the organization of the membership.
	Org *store.Organization
	// Membership is the row after the change. It holds the removed row for a
	// removal.
	Membership *store.Membership
	// From is the role before a role change. It is empty for another change.
	From string
	// Actor is the person who runs the change.
	Actor *store.User
	// Tx is the transactional store of the running change.
	Tx store.Store
}

// Organization hook function types.
type (
	// BeforeOrganizationCreateFunc runs in the transaction and can reject.
	BeforeOrganizationCreateFunc func(ctx context.Context, ev *OrganizationEvent) error
	// AfterOrganizationCreateFunc runs after commit.
	AfterOrganizationCreateFunc func(ctx context.Context, ev *OrganizationEvent) error
	// BeforeOrganizationUpdateFunc runs in the transaction and can reject.
	BeforeOrganizationUpdateFunc func(ctx context.Context, ev *OrganizationEvent) error
	// AfterOrganizationUpdateFunc runs after commit.
	AfterOrganizationUpdateFunc func(ctx context.Context, ev *OrganizationEvent) error
	// BeforeOrganizationDeleteFunc runs in the transaction and can reject. The
	// application removes its own rows of the organization here.
	BeforeOrganizationDeleteFunc func(ctx context.Context, ev *OrganizationEvent) error
	// AfterOrganizationDeleteFunc runs after commit.
	AfterOrganizationDeleteFunc func(ctx context.Context, ev *OrganizationEvent) error
	// BeforeMembershipChangeFunc runs in the transaction and can reject.
	BeforeMembershipChangeFunc func(ctx context.Context, ev *MembershipEvent) error
	// AfterMembershipChangeFunc runs after commit.
	AfterMembershipChangeFunc func(ctx context.Context, ev *MembershipEvent) error
)

// OnBeforeOrganizationCreate registers a hook that runs in the transaction and
// can reject.
func (h *Hooks) OnBeforeOrganizationCreate(fn BeforeOrganizationCreateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeOrgCreate = append(h.beforeOrgCreate, fn)
}

// OnAfterOrganizationCreate registers a hook that runs after commit.
func (h *Hooks) OnAfterOrganizationCreate(fn AfterOrganizationCreateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterOrgCreate = append(h.afterOrgCreate, fn)
}

// OnBeforeOrganizationUpdate registers a hook that runs in the transaction and
// can reject.
func (h *Hooks) OnBeforeOrganizationUpdate(fn BeforeOrganizationUpdateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeOrgUpdate = append(h.beforeOrgUpdate, fn)
}

// OnAfterOrganizationUpdate registers a hook that runs after commit.
func (h *Hooks) OnAfterOrganizationUpdate(fn AfterOrganizationUpdateFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterOrgUpdate = append(h.afterOrgUpdate, fn)
}

// OnBeforeOrganizationDelete registers a hook that runs in the transaction and
// can reject.
func (h *Hooks) OnBeforeOrganizationDelete(fn BeforeOrganizationDeleteFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeOrgDelete = append(h.beforeOrgDelete, fn)
}

// OnAfterOrganizationDelete registers a hook that runs after commit.
func (h *Hooks) OnAfterOrganizationDelete(fn AfterOrganizationDeleteFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterOrgDelete = append(h.afterOrgDelete, fn)
}

// OnBeforeMembershipChange registers a hook that runs in the transaction and
// can reject.
func (h *Hooks) OnBeforeMembershipChange(fn BeforeMembershipChangeFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.beforeMembership = append(h.beforeMembership, fn)
}

// OnAfterMembershipChange registers a hook that runs after commit.
func (h *Hooks) OnAfterMembershipChange(fn AfterMembershipChangeFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.afterMembership = append(h.afterMembership, fn)
}

// RunBeforeOrganizationCreate runs the registered hooks and stops at the first
// error.
func (h *Hooks) RunBeforeOrganizationCreate(ctx context.Context, ev *OrganizationEvent) error {
	h.mu.RLock()
	fns := append([]BeforeOrganizationCreateFunc(nil), h.beforeOrgCreate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// RunBeforeOrganizationUpdate runs the registered hooks and stops at the first
// error.
func (h *Hooks) RunBeforeOrganizationUpdate(ctx context.Context, ev *OrganizationEvent) error {
	h.mu.RLock()
	fns := append([]BeforeOrganizationUpdateFunc(nil), h.beforeOrgUpdate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// RunBeforeOrganizationDelete runs the registered hooks and stops at the first
// error.
func (h *Hooks) RunBeforeOrganizationDelete(ctx context.Context, ev *OrganizationEvent) error {
	h.mu.RLock()
	fns := append([]BeforeOrganizationDeleteFunc(nil), h.beforeOrgDelete...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// RunBeforeMembershipChange runs the registered hooks and stops at the first
// error.
func (h *Hooks) RunBeforeMembershipChange(ctx context.Context, ev *MembershipEvent) error {
	h.mu.RLock()
	fns := append([]BeforeMembershipChangeFunc(nil), h.beforeMembership...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			return err
		}
	}
	return nil
}

// RunAfterOrganizationCreate runs the registered hooks after commit.
func (h *Hooks) RunAfterOrganizationCreate(ctx context.Context, ev *OrganizationEvent) {
	h.mu.RLock()
	fns := append([]AfterOrganizationCreateFunc(nil), h.afterOrgCreate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			h.report(ctx, "after_organization_create", err)
		}
	}
}

// RunAfterOrganizationUpdate runs the registered hooks after commit.
func (h *Hooks) RunAfterOrganizationUpdate(ctx context.Context, ev *OrganizationEvent) {
	h.mu.RLock()
	fns := append([]AfterOrganizationUpdateFunc(nil), h.afterOrgUpdate...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			h.report(ctx, "after_organization_update", err)
		}
	}
}

// RunAfterOrganizationDelete runs the registered hooks after commit.
func (h *Hooks) RunAfterOrganizationDelete(ctx context.Context, ev *OrganizationEvent) {
	h.mu.RLock()
	fns := append([]AfterOrganizationDeleteFunc(nil), h.afterOrgDelete...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			h.report(ctx, "after_organization_delete", err)
		}
	}
}

// RunAfterMembershipChange runs the registered hooks after commit.
func (h *Hooks) RunAfterMembershipChange(ctx context.Context, ev *MembershipEvent) {
	h.mu.RLock()
	fns := append([]AfterMembershipChangeFunc(nil), h.afterMembership...)
	h.mu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, ev); err != nil {
			h.report(ctx, "after_membership_change", err)
		}
	}
}
