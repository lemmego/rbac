// Package rbacauthz puts a database-backed role system behind lemmego/authz,
// without changing authz at all.
//
// Prefix-named rather than rbac/authz, because that would collide with
// lemmego/authz at every import site — the same reason i18n's Inertia
// bridge is i18ninertia.
//
// # Why this is a separate module rather than a feature of authz
//
// authz has no storage, no DDL and no migrations, and its argument is that
// a policy should be typed and reviewable in one place. Growing a database
// into it would change what it is. So this sits beside it and uses the two
// hooks it already exports.
//
// # Two hooks, and both are needed
//
// Install registers one authz.Gate per declared permission code, and one
// authz.Before for the system role. The division is forced by authz's own
// shapes rather than chosen:
//
//   - A Gate answers one named ability, so a gate per code is how a code
//     becomes checkable through authz.Allowed(c, "post.publish").
//
//   - Before is handed the subject and NOT the ability, so it cannot
//     implement per-code checks — but it is the only hook that runs for a
//     RESOURCE policy registered with authz.Register. Without it a member of
//     the system role would pass every gate and still be refused by an
//     ownership policy on somebody else's row, which is the opposite of what
//     "every permission" means.
//
// # An ability nobody declared is denied, and that is authz's doing
//
// authz refuses an unregistered ability before any Before hook runs, so the
// system role cannot be used to allow an ability this build does not
// declare. That is the right way round: the catalogue is the list of things
// that can be allowed, and a typo in a check is a denial rather than a
// silent pass.
package rbacauthz

import (
	"context"

	"github.com/lemmego/api/app"
	"github.com/lemmego/authz"

	"github.com/lemmego/rbac"
)

// contextKey is unexported so nothing outside this package can write the
// permission set a gate will read. A string key would let any package put a
// set on the context, which is an escalation shaped like a convenience.
type contextKey struct{}

// WithSet puts a subject's permissions on the request context.
//
// Called from whatever middleware loads them — usually from a cache keyed by
// rbac.CacheKey — before the handler runs. It is deliberately not done here:
// loading them needs a database or a cache, and this package has neither, so
// the one decision it would have to make is the one it has no business
// making.
func WithSet(ctx context.Context, set rbac.Set) context.Context {
	return context.WithValue(ctx, contextKey{}, set)
}

// SetFrom reads the permissions loaded for this request.
//
// The bool is "were any loaded", not "are any held". The difference is the
// whole point: a request whose middleware did not run, or whose load failed,
// must be refused rather than treated as a subject who happens to hold
// nothing — those are the same answer here but not in a log, and a caller
// that wants to distinguish them can.
func SetFrom(c app.Context) (rbac.Set, bool) {
	set, loaded := c.Request().Context().Value(contextKey{}).(rbac.Set)
	return set, loaded
}

// Options configures Install.
type Options struct {
	// SetOf reads the permission set for a request. Defaults to SetFrom.
	SetOf func(app.Context) (rbac.Set, bool)

	// SkipSystemRole leaves the Before hook uninstalled.
	//
	// For an application that wants permission gates and no blanket
	// override — or one that installs its own Before and would otherwise
	// have two. Off by default, because a role that means "everything" and
	// then loses to an ownership policy is a role that does not mean
	// everything.
	SkipSystemRole bool
}

// Install registers every declared permission as an authz gate, plus the
// system role's blanket allow.
//
// U is the application's user type, as authz uses it: the type its
// auth.UserLoader resolves. It appears only in the type parameter, because
// a permission check does not read the subject — the set was loaded by the
// middleware that knew who they were.
func Install[U any](r *authz.Registry, catalog *rbac.Catalog, opts Options) {
	setOf := opts.SetOf
	if setOf == nil {
		setOf = SetFrom
	}

	for _, code := range catalog.Codes() {
		authz.Gate[U](r, code, func(c app.Context, _ U) authz.Decision {
			set, loaded := setOf(c)
			if !loaded {
				return authz.Deny("no permissions were loaded for this request")
			}
			if set.Has(code) {
				return authz.Allow()
			}
			return authz.Deny("you do not have " + code)
		})
	}

	if opts.SkipSystemRole {
		return
	}

	authz.Before[U](r, func(c app.Context, _ U) (authz.Decision, bool) {
		set, loaded := setOf(c)
		if loaded && set.IsEverything() {
			return authz.Allow(), true
		}
		// Not handled, rather than denied. A Before hook that denied here
		// would refuse every check in the application for everybody who is
		// not in the system role, including ones this package knows nothing
		// about.
		return authz.Decision{}, false
	})
}
