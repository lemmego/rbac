package rbacauthz_test

import (
	"net/http"
	"testing"

	"github.com/lemmego/api/app"
	"github.com/lemmego/apptest"
	"github.com/lemmego/auth"
	"github.com/lemmego/authz"

	"github.com/lemmego/rbac"
	"github.com/lemmego/rbac/rbacauthz"
)

type user struct{ ID string }

func (u *user) GetID() string       { return u.ID }
func (u *user) GetUsername() string { return u.ID + "@example.test" }
func (u *user) GetPassword() string { return "" }

// A document owned by somebody, for the resource policy the system role has
// to be able to win.
type document struct{ OwnerID string }

func catalog(t *testing.T) *rbac.Catalog {
	t.Helper()
	c := rbac.NewCatalog()
	if err := c.Add(
		rbac.Permission{Code: "post.create", Module: "post", Description: "Write a post"},
		rbac.Permission{Code: "post.publish", Module: "post", Description: "Publish a post"},
		rbac.Permission{Code: "billing.read", Module: "billing", Description: "See the invoices"},
	); err != nil {
		t.Fatal(err)
	}
	return c
}

// boot builds an application whose permission set is whatever the test says,
// with the catalogue installed as gates and one ownership policy beside them.
func boot(t *testing.T, set rbac.Set, loaded bool) *apptest.App {
	t.Helper()
	return apptest.New(t,
		apptest.WithProviders(
			&auth.Provider{Opts: &auth.Opts{
				DisableSession: true,
				JwtSecret:      "rbacauthz-test",
				UserLoader: func(c app.Context, id string) (any, error) {
					return &user{ID: id}, nil
				},
			}},
			&authz.Provider{Policies: func(r *authz.Registry) {
				rbacauthz.Install[*user](r, catalog(t), rbacauthz.Options{
					SetOf: func(app.Context) (rbac.Set, bool) { return set, loaded },
				})
				// A resource policy, which no gate can answer and which the
				// system role must still win.
				authz.Register[*user, *document](r, "document.update",
					func(_ app.Context, u *user, d *document) authz.Decision {
						if d.OwnerID == u.ID {
							return authz.Allow()
						}
						return authz.Deny("you do not own this")
					})
			}},
		),
		apptest.WithRoutes(func(a app.App) {
			a.Router().Get("/gate/{code}", auth.OptionalAuth, func(c app.Context) error {
				if err := authz.AuthorizeGate(c, c.Param("code")); err != nil {
					return err
				}
				return c.JSON(app.M{"ok": true})
			})
			// Somebody else's document, always.
			a.Router().Get("/document", auth.OptionalAuth, func(c app.Context) error {
				if err := authz.Authorize(c, "document.update", &document{OwnerID: "somebody-else"}); err != nil {
					return err
				}
				return c.JSON(app.M{"ok": true})
			})
		}),
	)
}

// Each gate checks its own code.
//
// Holding ONE code allows exactly that one and refuses the others, which is
// the property a gate per code is for. Not a guard against a loop variable
// captured by reference — Go gives every iteration its own since 1.22, and
// a test cannot fail for a bug the language no longer has.
func TestAGateChecksItsOwnCodeAndNotAnother(t *testing.T) {
	a := boot(t, rbac.NewSet("post.publish"), true)

	for code, want := range map[string]int{
		"post.publish": http.StatusOK,
		"post.create":  http.StatusForbidden,
		"billing.read": http.StatusForbidden,
	} {
		res := a.Get("/gate/" + code).ActingAs("1").Send()
		if res.StatusCode != want {
			t.Errorf("holding only post.publish, %s answered %d, want %d",
				code, res.StatusCode, want)
		}
	}
}

// A request whose middleware never loaded a set is refused.
//
// The set handed over is Everything() — the one that allows all three gates
// and overrides the ownership policy — with "loaded" false. So this fails
// the moment the flag is ignored, which pairing it with an empty set would
// not: an empty set denies anyway, so the test would pass whether the flag
// were read or not. It was written that way first, and the probe caught it.
func TestNoPermissionsLoadedIsARefusal(t *testing.T) {
	a := boot(t, rbac.Everything(), false)

	if res := a.Get("/gate/post.publish").ActingAs("1").Send(); res.StatusCode != http.StatusForbidden {
		t.Errorf("an unloaded permission set passed a gate (%d), want 403", res.StatusCode)
	}
	// And the system role's override must not fire either, or a failed load
	// is an administrator.
	if res := a.Get("/document").ActingAs("1").Send(); res.StatusCode != http.StatusForbidden {
		t.Errorf("an unloaded permission set won an ownership policy (%d), want 403", res.StatusCode)
	}
}

// The zero Set grants nothing, which is the direction this has to fail.
func TestTheZeroSetAllowsNothing(t *testing.T) {
	a := boot(t, rbac.Set{}, true)

	for _, code := range []string{"post.create", "post.publish", "billing.read"} {
		if res := a.Get("/gate/" + code).ActingAs("1").Send(); res.StatusCode != http.StatusForbidden {
			t.Errorf("the zero set allowed %s (%d)", code, res.StatusCode)
		}
	}
}

// The system role passes every gate.
func TestTheSystemRolePassesEveryGate(t *testing.T) {
	a := boot(t, rbac.Everything(), true)

	for _, code := range []string{"post.create", "post.publish", "billing.read"} {
		if res := a.Get("/gate/" + code).ActingAs("1").Send(); res.StatusCode != http.StatusOK {
			t.Errorf("the system role was refused %s (%d)", code, res.StatusCode)
		}
	}
}

// And wins an ownership policy, which is the Before hook's entire purpose.
//
// No gate can answer this: document.update is registered with a resource,
// so it is not a gate at all. A member of the system role who passed every
// permission gate and was then refused somebody else's document would be in
// a role that does not mean what it says.
func TestTheSystemRoleWinsAResourcePolicy(t *testing.T) {
	// Somebody holding every declared permission but NOT the system role is
	// still refused, which is what makes the next assertion about the role
	// rather than about permissions.
	ordinary := boot(t, rbac.NewSet("post.create", "post.publish", "billing.read"), true)
	if res := ordinary.Get("/document").ActingAs("1").Send(); res.StatusCode != http.StatusForbidden {
		t.Fatalf("every permission was enough to own somebody else's document (%d)", res.StatusCode)
	}

	system := boot(t, rbac.Everything(), true)
	if res := system.Get("/document").ActingAs("1").Send(); res.StatusCode != http.StatusOK {
		t.Fatalf("the system role was refused somebody else's document (%d), so it does not "+
			"mean every permission", res.StatusCode)
	}
}

// An ability nobody declared is refused even for the system role.
//
// authz denies an unregistered ability before any Before hook runs, which is
// the right way round and is asserted here rather than assumed: it means a
// typo in a check is a denial, not a pass for whoever happens to be an
// administrator.
func TestAnUndeclaredAbilityIsRefusedEvenForTheSystemRole(t *testing.T) {
	a := boot(t, rbac.Everything(), true)

	res := a.Get("/gate/post.pubish").ActingAs("1").Send()
	if res.StatusCode == http.StatusOK {
		t.Fatal("a misspelled ability was allowed for the system role")
	}
}

// SkipSystemRole leaves the gates and drops the override.
func TestSkippingTheSystemRoleLeavesTheGates(t *testing.T) {
	a := apptest.New(t,
		apptest.WithProviders(
			&auth.Provider{Opts: &auth.Opts{
				DisableSession: true,
				JwtSecret:      "rbacauthz-test",
				UserLoader: func(c app.Context, id string) (any, error) {
					return &user{ID: id}, nil
				},
			}},
			&authz.Provider{Policies: func(r *authz.Registry) {
				rbacauthz.Install[*user](r, catalog(t), rbacauthz.Options{
					SetOf:          func(app.Context) (rbac.Set, bool) { return rbac.Everything(), true },
					SkipSystemRole: true,
				})
				authz.Register[*user, *document](r, "document.update",
					func(_ app.Context, u *user, d *document) authz.Decision {
						if d.OwnerID == u.ID {
							return authz.Allow()
						}
						return authz.Deny("you do not own this")
					})
			}},
		),
		apptest.WithRoutes(func(a app.App) {
			a.Router().Get("/gate/{code}", auth.OptionalAuth, func(c app.Context) error {
				if err := authz.AuthorizeGate(c, c.Param("code")); err != nil {
					return err
				}
				return c.JSON(app.M{"ok": true})
			})
			a.Router().Get("/document", auth.OptionalAuth, func(c app.Context) error {
				if err := authz.Authorize(c, "document.update", &document{OwnerID: "somebody-else"}); err != nil {
					return err
				}
				return c.JSON(app.M{"ok": true})
			})
		}),
	)

	// Everything() still satisfies a gate, because Set.Has answers true.
	if res := a.Get("/gate/post.publish").ActingAs("1").Send(); res.StatusCode != http.StatusOK {
		t.Errorf("a gate was refused with SkipSystemRole (%d)", res.StatusCode)
	}
	// But the resource policy is no longer overridden, which is the whole
	// difference the option makes.
	if res := a.Get("/document").ActingAs("1").Send(); res.StatusCode != http.StatusForbidden {
		t.Errorf("the resource policy was overridden with SkipSystemRole (%d)", res.StatusCode)
	}
}
