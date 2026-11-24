# rbac

Database-backed roles and permissions for a Lemmego application, behind
[`lemmego/authz`](https://github.com/lemmego/authz) rather than instead of it.

```go
import (
    "github.com/lemmego/rbac"
    "github.com/lemmego/rbac/rbacstore"
    "github.com/lemmego/rbac/rbacauthz"
)
```

`authz` gives you typed policies, reviewable in one place. This gives you the
part a policy cannot be: a role an administrator creates at runtime, a
permission somebody ticks in a form, and a set of them that changes without a
deploy.

## Why a separate module

`authz` has no storage, no DDL and no migrations, and its whole argument is
that a policy should be typed and reviewable in one place. Growing a database
into it would change what it is. So this sits beside it and uses the two hooks
it already exports — **`authz` is not modified at all**, and an application
that wants only typed policies links none of this.

## A scope is an opaque string

Every role, grant and assignment belongs to a scope, and this module never
asks what one is.

```go
store := rbacstore.New(rbacstore.Config{})            // multi-tenant: the ORM's bound tenant
store := rbacstore.New(rbacstore.Config{              // single-tenant: one scope, always
    ScopeOf: rbacstore.Unscoped(""),
})
```

That is what keeps this independent of any particular notion of tenancy: it
imports none, and a tenancy module does not have to know this exists. The
default reads the tenant the ORM transaction is bound to, and **that direction
is deliberate** — the other default, one scope for everybody, would mean a
multi-tenant application that forgot to configure it shares one set of roles
across every tenant, silently, with every test passing. A single-tenant
application that has not configured it instead gets `ErrNoScope` on its first
call.

A subject is an opaque string too: a user, a service account, an API key. An
application may key its people on an integer, a uuid, or a qualified pair like
`user:42` when administrators live in a different table from customers — and a
library that picked one of those would be unusable by the applications that
picked another.

## The scope comes off the handle, never from an argument

```go
func (h *Handler) Grant(c app.Context) error {
    return h.db.TenantTx(c.RequestContext(), workspaceID, func(tx *orm.Tx) error {
        return h.roles.Grant(c.RequestContext(), tx, roleID, "post.publish")
    })
}
```

There is no spelling of any of these calls that could name a scope other than
the one the transaction is in. A scope parameter would be one more thing a
caller could get wrong, in the one place where getting it wrong is a
cross-tenant write.

## Two authz hooks, and both are needed

```go
&authz.Provider{Policies: func(r *authz.Registry) {
    rbacauthz.Install[*models.User](r, catalog, rbacauthz.Options{})
}}
```

`Install` registers **one `authz.Gate` per declared permission code** plus
**one `authz.Before`** for the system role. The division is forced by `authz`'s
own shapes rather than chosen:

- A `Gate` answers one named ability, so a gate per code is how a code becomes
  checkable through `authz.Allowed(c, "post.publish")`.
- `Before` is handed the subject and **not** the ability, so it cannot
  implement per-code checks — but it is the only hook that runs for a resource
  policy registered with `authz.Register`. Without it, a member of the system
  role would pass every permission gate and still be refused by an ownership
  policy on somebody else's row, which is the opposite of what "every
  permission" means.

**An ability nobody declared is denied**, and that is `authz`'s doing: it
refuses an unregistered ability before any `Before` hook runs. So the system
role cannot be used to allow something this build does not declare, and a typo
in a check is a denial rather than a silent pass for whoever happens to be an
administrator.

## The permission set reaches the gate through the context

Loading it needs a database or a cache, and this module's gates have neither —
so the one decision they would have to make is the one they have no business
making.

```go
// In middleware, after auth has run.
set, err := store.PermissionsOf(c.RequestContext(), tx, subject)
c.WithContext(rbacauthz.WithSet(c.RequestContext(), set))
```

`SetFrom` answers `(Set, bool)`, and the bool is **"were any loaded"**, not
"are any held". A request whose middleware did not run, or whose load failed,
is refused rather than treated as a subject who happens to hold nothing.

## The system role holds no grants at all

One per scope, created with it, and `is_system` in the database. Three
consequences follow, and each is the reason rather than a side effect:

- it cannot be partially revoked, because there is no grant to delete;
- a new module adds nothing to migrate into it;
- "who can do everything here" is a membership of one role rather than a set of
  grants somebody has to keep complete.

Two triggers hold that, and they hold against **anything** that writes the
tables — a migration, a fixture, a `psql` session — not only against this
package:

- granting a permission to the system role raises, so it cannot quietly become
  a list of codes that revoking one would appear to change;
- renaming, demoting, deleting or soft-deleting it raises.

The second needs an escape hatch, because a scope has to be removable:
`SELECT set_config('rbac.purge', 'on', true)` in the same transaction as the
delete. Transaction-local, so it resets at commit or rollback and cannot reach
the next user of a pooled connection — and **explicit rather than absent**,
because without it the first person who needed to hard-delete a scope would
reach for `DROP TRIGGER` and leave it off.

## The schema is yours

```go
for _, statement := range rbacstore.SchemaStatements(rbacstore.SchemaConfig{
    Config:            cfg,
    ScopeType:         "uuid",
    ScopeReferences:   "workspaces (id)",
    SubjectReferences: "users (workspace_id, id)",
}) {
    if _, err := tx.Exec(statement); err != nil {
        return err
    }
}
```

Statements rather than a `Migrate` call, so it is the application's migration —
its to read, review, edit and roll back, and findable in whatever table its
migrator records. A library that created its own tables at boot would put
tables in somebody's database that nothing in their project mentions.

Table and column names come from `Config` and are interpolated once, in `New`,
because a placeholder cannot carry an identifier in any SQL dialect. **Nothing
from a request ever reaches that interpolation**: the values are an
application's own schema, fixed at boot, and everything that varies per call is
bound.

Three things in the DDL are not portable and not incidental: a **partial
unique index**, so a soft-deleted role's name is free again rather than
reserved forever; **plpgsql triggers**, per above; and **`ON CONFLICT`**, which
the idempotent writes rely on.

`SubjectReferences` is **blank by default**, and that is honest rather than
lazy. A framework cannot know whether subjects live in one table, in three, or
outside the database — and a single-column reference to a `users` table would
be *wrong* even where one exists: PostgreSQL checks a foreign key with the
referenced table's owner rights, which **bypasses row-level security**, so a
non-composite reference will happily accept another scope's user. Hence the
composite form, and hence `roles` carrying `UNIQUE (scope, id)` for the pivots
to point at.

## Syncing the catalogue never deletes

```go
n, err := store.SyncPermissions(ctx, db, catalog)
if errors.Is(err, rbacstore.ErrNotMigrated) {
    // Normal on a fresh database. Log it and boot, or the command that runs
    // the migrations cannot start.
}
```

A code in the table and not in the catalogue is left alone, and that is
required rather than cautious: modules are compiled selectively, so a build
without one module would otherwise delete every permission it declared —
cascading to every grant that referenced one — and a later build with the
module back would find the roles silently emptied.

## Verification

```bash
export RBAC_POSTGRES_DSN="postgres://$USER@127.0.0.1:5432/rbac_test?sslmode=disable"
go test ./... -count=1 -v
go test ./... -race
GOWORK=off go test ./...
```

The store suite **fails rather than skips** without a DSN. It exercises
PostgreSQL triggers, a partial unique index and composite foreign keys, none of
which SQLite has — so skipping it would leave the DDL this module ships
untested, and a skip and a pass share an exit code.

It also runs against a deliberately **non-default** schema throughout —
`rbactest_roles`, `workspace_id`, `principal`, a system role called `owner` —
because a suite that uses the defaults proves the defaults and not the
configuration, and the configuration is what makes this usable by an
application whose tables are already named something else.
