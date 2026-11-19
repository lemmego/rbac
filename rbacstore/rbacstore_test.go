package rbacstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/lemmego/orm"

	"github.com/lemmego/rbac"
	"github.com/lemmego/rbac/rbacstore"
)

// A deliberately non-default schema throughout, because a test that uses the
// defaults proves the defaults and not the configuration — and the
// configuration is what makes this module usable by an application whose
// tables are already named something else.
func schema() rbacstore.SchemaConfig {
	return rbacstore.SchemaConfig{
		Config: rbacstore.Config{
			RolesTable:       "rbactest_roles",
			GrantsTable:      "rbactest_grants",
			AssignmentsTable: "rbactest_assignments",
			PermissionsTable: "rbactest_permissions",
			ScopeColumn:      "workspace_id",
			SubjectColumn:    "principal",
			SystemRole:       "owner",
		},
		PurgeSetting: "rbactest.purge",
		Prefix:       "rbactest",
	}
}

func connect(t *testing.T, dsn string) *orm.DB {
	t.Helper()
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("opening postgres: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return orm.Open(sqlDB, orm.Postgres())
}

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

// open builds the schema fresh and hands back a handle plus the store.
func open(t *testing.T) (*orm.DB, *rbacstore.Store) {
	t.Helper()

	dsn := os.Getenv("RBAC_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("RBAC_POSTGRES_DSN is not set.\n\n" +
			"This suite exercises PostgreSQL triggers, a partial unique index and " +
			"composite foreign keys, none of which SQLite has — so skipping it would " +
			"leave the DDL this package ships untested, and a skip and a pass share " +
			"an exit code.")
	}

	db := connect(t, dsn)

	ctx := context.Background()
	drop := rbacstore.DropStatements(schema())
	for _, statement := range drop {
		if _, err := db.SQLDB().ExecContext(ctx, statement); err != nil {
			t.Fatalf("clearing: %v", err)
		}
	}
	for _, statement := range rbacstore.SchemaStatements(schema()) {
		if _, err := db.SQLDB().ExecContext(ctx, statement); err != nil {
			t.Fatalf("creating the schema: %v\n\nstatement:\n%s", err, statement)
		}
	}
	t.Cleanup(func() {
		for _, statement := range drop {
			_, _ = db.SQLDB().ExecContext(context.Background(), statement)
		}
	})

	store := rbacstore.New(schema().Config)
	if _, err := store.SyncPermissions(ctx, db, catalog(t)); err != nil {
		t.Fatalf("syncing the catalogue: %v", err)
	}
	return db, store
}

// systemRole gives a scope the role that means everything.
func systemRole(t *testing.T, db *orm.DB, scope string) int64 {
	t.Helper()
	var id int64
	if err := db.SQLDB().QueryRowContext(context.Background(),
		rbacstore.CreateSystemRole(schema().Config), scope).Scan(&id); err != nil {
		t.Fatalf("creating the system role for %s: %v", scope, err)
	}
	return id
}

// in runs fn inside a transaction bound to a scope, which is how every
// method here is meant to be called.
func in(t *testing.T, db *orm.DB, scope string, fn func(*orm.Tx)) {
	t.Helper()
	if err := db.TenantTx(context.Background(), scope, func(tx *orm.Tx) error {
		fn(tx)
		return nil
	}); err != nil {
		t.Fatalf("in scope %s: %v", scope, err)
	}
}

// inFailing runs fn in a scoped transaction and always rolls back, for a
// case that deliberately provokes a database error.
//
// PostgreSQL aborts the entire transaction on the first failed statement, so
// any later assertion in the same one fails with "could not complete
// operation in a failed transaction" — for the wrong reason — and so does
// the commit. A case that expects a refusal therefore gets a transaction to
// itself.
func inFailing(t *testing.T, db *orm.DB, scope string, fn func(*orm.Tx)) {
	t.Helper()
	deliberate := errors.New("rolling back deliberately")
	if err := db.TenantTx(context.Background(), scope, func(tx *orm.Tx) error {
		fn(tx)
		return deliberate
	}); err != nil && !errors.Is(err, deliberate) {
		t.Fatalf("in scope %s: %v", scope, err)
	}
}

// The whole round trip, in a configured schema rather than the default one.
func TestARoleIsCreatedGrantedAssignedAndRead(t *testing.T) {
	db, store := open(t)
	ctx := context.Background()

	var editor rbacstore.Role
	in(t, db, "acme", func(tx *orm.Tx) {
		var err error
		editor, err = store.CreateRole(ctx, tx, "Editor", "Writes and publishes")
		if err != nil {
			t.Fatalf("creating a role: %v", err)
		}
		if editor.IsSystem {
			t.Error("CreateRole made a system role")
		}
		if err := store.Grant(ctx, tx, editor.ID, "post.create"); err != nil {
			t.Fatal(err)
		}
		if err := store.Grant(ctx, tx, editor.ID, "post.publish"); err != nil {
			t.Fatal(err)
		}
		// Twice, because every write here claims to be idempotent.
		if err := store.Grant(ctx, tx, editor.ID, "post.publish"); err != nil {
			t.Fatalf("granting twice: %v", err)
		}
		if err := store.Assign(ctx, tx, "user:1", editor.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.Assign(ctx, tx, "user:1", editor.ID); err != nil {
			t.Fatalf("assigning twice: %v", err)
		}
	})

	in(t, db, "acme", func(tx *orm.Tx) {
		set, err := store.PermissionsOf(ctx, tx, "user:1")
		if err != nil {
			t.Fatal(err)
		}
		if set.IsEverything() {
			t.Fatal("an ordinary role answered as the system role")
		}
		if got := strings.Join(set.Codes(), ","); got != "post.create,post.publish" {
			t.Errorf("permissions = %q", got)
		}
		if set.Has("billing.read") {
			t.Error("a code that was never granted is held")
		}

		codes, err := store.Grants(ctx, tx, editor.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(codes) != 2 {
			t.Errorf("grants = %v", codes)
		}

		if err := store.Revoke(ctx, tx, editor.ID, "post.publish"); err != nil {
			t.Fatal(err)
		}
		set, _ = store.PermissionsOf(ctx, tx, "user:1")
		if set.Has("post.publish") {
			t.Error("a revoked code is still held")
		}
	})
}

// The system role answers Everything even though it holds no grants at all.
//
// This is the case an inner join would get wrong: there are no rows in the
// grants table for this role, so a join that required one would return
// nothing and the answer would be an empty set — which denies. The one
// subject allowed everything would be allowed nothing.
func TestTheSystemRoleHoldsEverythingWithNoGrants(t *testing.T) {
	db, store := open(t)
	ctx := context.Background()

	roleID := systemRole(t, db, "acme")

	in(t, db, "acme", func(tx *orm.Tx) {
		if err := store.Assign(ctx, tx, "user:9", roleID); err != nil {
			t.Fatal(err)
		}
		set, err := store.PermissionsOf(ctx, tx, "user:9")
		if err != nil {
			t.Fatal(err)
		}
		if !set.IsEverything() {
			t.Fatalf("the system role answered %v, not Everything", set.Codes())
		}

		codes, err := store.Grants(ctx, tx, roleID)
		if err != nil {
			t.Fatal(err)
		}
		if len(codes) != 0 {
			t.Errorf("the system role holds grants in the database: %v", codes)
		}
	})
}

// Two scopes, and nothing crosses — through this package's own statements,
// which carry no implicit predicate at all.
func TestOneScopeCannotSeeAnother(t *testing.T) {
	db, store := open(t)
	ctx := context.Background()

	var acmeRole rbacstore.Role
	in(t, db, "acme", func(tx *orm.Tx) {
		var err error
		acmeRole, err = store.CreateRole(ctx, tx, "Editor", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Grant(ctx, tx, acmeRole.ID, "post.create"); err != nil {
			t.Fatal(err)
		}
		if err := store.Assign(ctx, tx, "user:1", acmeRole.ID); err != nil {
			t.Fatal(err)
		}
	})

	in(t, db, "globex", func(tx *orm.Tx) {
		roles, err := store.Roles(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}
		if len(roles) != 0 {
			t.Errorf("globex sees acme's roles: %+v", roles)
		}

		// The same subject, in the other scope, holds nothing.
		set, err := store.PermissionsOf(ctx, tx, "user:1")
		if err != nil {
			t.Fatal(err)
		}
		if set.Len() != 0 || set.IsEverything() {
			t.Errorf("a subject's permissions crossed scopes: %v", set.Codes())
		}

		// And acme's role cannot be reached by id, which is the one way a
		// caller could try: the id is a bigserial and therefore guessable.
		if _, err := store.Grants(ctx, tx, acmeRole.ID); err == nil {
			if codes, _ := store.Grants(ctx, tx, acmeRole.ID); len(codes) != 0 {
				t.Errorf("another scope's grants were readable by role id: %v", codes)
			}
		}
		if err := store.DeleteRole(ctx, tx, acmeRole.ID); !errors.Is(err, rbacstore.ErrNoRole) {
			t.Errorf("deleting another scope's role gave %v, want ErrNoRole", err)
		}
	})

	// And acme still has it.
	in(t, db, "acme", func(tx *orm.Tx) {
		roles, err := store.Roles(ctx, tx)
		if err != nil || len(roles) != 1 {
			t.Fatalf("acme's roles = %+v, %v", roles, err)
		}
	})
}

// An unbound handle reads nothing rather than everything.
func TestAnUnboundHandleIsRefused(t *testing.T) {
	db, store := open(t)
	ctx := context.Background()

	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := store.PermissionsOf(ctx, tx, "user:1"); !errors.Is(err, rbacstore.ErrNoScope) {
		t.Errorf("an unbound handle gave %v, want ErrNoScope", err)
	}
	if _, err := store.Roles(ctx, tx); !errors.Is(err, rbacstore.ErrNoScope) {
		t.Errorf("Roles on an unbound handle gave %v, want ErrNoScope", err)
	}
	if err := store.Grant(ctx, tx, 1, "post.create"); !errors.Is(err, rbacstore.ErrNoScope) {
		t.Errorf("Grant on an unbound handle gave %v, want ErrNoScope", err)
	}
}

// The database protects the system role, not just this package.
//
// Asserted through raw SQL rather than through the store, because the store
// could be bypassed by a migration, a fixture or a psql session — and the
// protection is only worth having if it holds against those too.
func TestTheDatabaseProtectsTheSystemRole(t *testing.T) {
	db, _ := open(t)
	ctx := context.Background()
	roleID := systemRole(t, db, "acme")
	sqlDB := db.SQLDB()

	if _, err := sqlDB.ExecContext(ctx,
		`DELETE FROM rbactest_roles WHERE id = $1`, roleID); err == nil {
		t.Error("the system role was deleted by raw SQL")
	}
	if _, err := sqlDB.ExecContext(ctx,
		`UPDATE rbactest_roles SET name = 'sneaky' WHERE id = $1`, roleID); err == nil {
		t.Error("the system role was renamed by raw SQL")
	}
	if _, err := sqlDB.ExecContext(ctx,
		`UPDATE rbactest_roles SET is_system = false WHERE id = $1`, roleID); err == nil {
		t.Error("the system role was demoted by raw SQL")
	}
	if _, err := sqlDB.ExecContext(ctx,
		`UPDATE rbactest_roles SET deleted_at = now() WHERE id = $1`, roleID); err == nil {
		t.Error("the system role was soft-deleted by raw SQL")
	}

	// And it holds no grants, by the other trigger.
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO rbactest_grants (workspace_id, role_id, permission_code)
		 VALUES ('acme', $1, 'post.create')`, roleID); err == nil {
		t.Error("the system role was granted a permission, so it is a list of codes " +
			"rather than everything")
	}

	// A second system role in one scope is refused, and under a DIFFERENT
	// name — because CreateSystemRole always writes the same one, so a
	// second call is refused by the unique name index whatever the is_system
	// index says, and the test would pass with that index broken. The probe
	// caught exactly that.
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO rbactest_roles (workspace_id, name, description, is_system)
		 VALUES ('acme', 'second owner', '', true)`); err == nil {
		t.Error("a scope took a second system role under another name, so two subjects " +
			"could hold 'everything' and revoking one would change nothing")
	}
}

// The purge setting is the one way through, and it is transaction-local.
func TestOnlyAPurgeCanRemoveTheSystemRole(t *testing.T) {
	db, _ := open(t)
	ctx := context.Background()
	roleID := systemRole(t, db, "acme")

	tx, err := db.SQLDB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config('rbactest.purge', 'on', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM rbactest_roles WHERE id = $1`, roleID); err != nil {
		t.Fatalf("a purge could not delete the system role: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// The setting was transaction-local, so the next statement on a pooled
	// connection is protected again. A session-level SET would leave every
	// later request able to delete a system role, and would look identical
	// in development.
	again := systemRole(t, db, "acme")
	if _, err := db.SQLDB().ExecContext(ctx,
		`DELETE FROM rbactest_roles WHERE id = $1`, again); err == nil {
		t.Error("the purge setting outlived its transaction")
	}
}

// A soft-deleted role frees its name, and stops granting.
func TestASoftDeletedRoleFreesItsNameAndGrantsNothing(t *testing.T) {
	db, store := open(t)
	ctx := context.Background()

	in(t, db, "acme", func(tx *orm.Tx) {
		role, err := store.CreateRole(ctx, tx, "Editor", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Grant(ctx, tx, role.ID, "post.create"); err != nil {
			t.Fatal(err)
		}
		if err := store.Assign(ctx, tx, "user:1", role.ID); err != nil {
			t.Fatal(err)
		}
	})

	// A duplicate name is refused while it is live, case-insensitively.
	inFailing(t, db, "acme", func(tx *orm.Tx) {
		if _, err := store.CreateRole(ctx, tx, "editor", ""); err == nil {
			t.Error("two live roles took the same name, case-insensitively")
		}
	})

	in(t, db, "acme", func(tx *orm.Tx) {
		role, err := store.RoleNamed(ctx, tx, "EDITOR")
		if err != nil {
			t.Fatalf("RoleNamed is case-sensitive: %v", err)
		}
		if err := store.DeleteRole(ctx, tx, role.ID); err != nil {
			t.Fatal(err)
		}
		// Gone from the listing.
		roles, _ := store.Roles(ctx, tx)
		if len(roles) != 0 {
			t.Errorf("a soft-deleted role is still listed: %+v", roles)
		}
		// And grants nothing, although its assignment row survives — which
		// is why the permissions query filters on the role's deleted_at and
		// not only on the assignment.
		set, err := store.PermissionsOf(ctx, tx, "user:1")
		if err != nil {
			t.Fatal(err)
		}
		if set.Len() != 0 {
			t.Errorf("a soft-deleted role still grants %v", set.Codes())
		}
		// The name is free again.
		if _, err := store.CreateRole(ctx, tx, "Editor", "the second one"); err != nil {
			t.Errorf("a soft-deleted role reserved its name forever: %v", err)
		}
	})
}

// An undeclared code cannot be granted, because the catalogue is in the
// database as a foreign key rather than only in Go.
func TestAnUndeclaredCodeCannotBeGranted(t *testing.T) {
	db, store := open(t)
	ctx := context.Background()

	inFailing(t, db, "acme", func(tx *orm.Tx) {
		role, err := store.CreateRole(ctx, tx, "Editor", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Grant(ctx, tx, role.ID, "post.pubish"); err == nil {
			t.Error("a misspelled permission code was granted")
		}
	})
}

// Syncing never deletes, which is what makes a selectively compiled build
// safe: a build without one module must not delete that module's
// permissions and cascade away every grant of them.
func TestSyncingNeverDeletes(t *testing.T) {
	db, store := open(t)
	ctx := context.Background()

	smaller := rbac.NewCatalog()
	if err := smaller.Add(rbac.Permission{
		Code: "post.create", Module: "post", Description: "Write a post",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SyncPermissions(ctx, db, smaller); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := db.SQLDB().QueryRowContext(ctx,
		`SELECT count(*) FROM rbactest_permissions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("syncing a smaller catalogue left %d permissions, want all 3 — a build "+
			"without a module would have deleted its codes and every grant of them", count)
	}
}

// An unmigrated database is a named state rather than a driver error, so a
// provider can boot and let the migration command run.
func TestAnUnmigratedDatabaseSaysSo(t *testing.T) {
	dsn := os.Getenv("RBAC_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("RBAC_POSTGRES_DSN is not set")
	}
	db := connect(t, dsn)

	cfg := schema().Config
	cfg.PermissionsTable = "rbactest_absent_permissions"
	store := rbacstore.New(cfg)

	if _, err := store.SyncPermissions(context.Background(), db, catalog(t)); !errors.Is(err, rbacstore.ErrNotMigrated) {
		t.Fatalf("an unmigrated database gave %v, want ErrNotMigrated", err)
	}
}

// A subject column that is not text needs no special configuration, and
// that is worth a test because it is not obvious.
//
// A subject is an opaque STRING to this package and every statement binds it
// as one, so a bigint column looks like it should fail with "operator does
// not exist: bigint = text". It does not: the driver sends the parameter
// untyped and PostgreSQL infers the type from the column it is compared to
// or inserted into.
//
// The reason an application wants such a column is a safety property rather
// than a preference. With the subject a bigint referencing the users table,
// a composite foreign key (scope, subject) makes a cross-scope assignment
// unrepresentable — and Postgres checks a foreign key with the referenced
// table's owner rights, so it BYPASSES row-level security. A text subject
// with no foreign key at all would quietly lose that guarantee.
//
// So this is the configuration a careful application reaches for, and this
// test is what says it is supported. It was written after a cast knob was
// added for it and then removed: probing the new code found that nothing
// broke without it, which meant the knob was decoration and the real fix
// for the application was a column NAME it had configured wrongly.
func TestASubjectColumnThatIsNotTextWorksUnchanged(t *testing.T) {
	dsn := os.Getenv("RBAC_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("RBAC_POSTGRES_DSN is not set")
	}
	db := connect(t, dsn)

	cfg := schema()
	cfg.AssignmentsTable = "rbactest_numeric_assignments"
	cfg.SubjectColumn = "principal_id"
	cfg.SubjectType = "bigint"

	ctx := context.Background()
	drop := rbacstore.DropStatements(cfg)
	for _, statement := range drop {
		if _, err := db.SQLDB().ExecContext(ctx, statement); err != nil {
			t.Fatalf("clearing: %v", err)
		}
	}
	for _, statement := range rbacstore.SchemaStatements(cfg) {
		if _, err := db.SQLDB().ExecContext(ctx, statement); err != nil {
			t.Fatalf("creating the schema: %v\n\nstatement:\n%s", err, statement)
		}
	}
	t.Cleanup(func() {
		for _, statement := range drop {
			_, _ = db.SQLDB().ExecContext(context.Background(), statement)
		}
	})

	store := rbacstore.New(cfg.Config)
	if _, err := store.SyncPermissions(ctx, db, catalog(t)); err != nil {
		t.Fatalf("syncing the catalogue: %v", err)
	}

	in(t, db, "acme", func(tx *orm.Tx) {
		role, err := store.CreateRole(ctx, tx, "Editor", "Edits things")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Grant(ctx, tx, role.ID, "post.create"); err != nil {
			t.Fatal(err)
		}
		// A decimal subject, which is what an application keying on a user
		// id passes.
		if err := store.Assign(ctx, tx, "42", role.ID); err != nil {
			t.Fatalf("assigning a numeric subject: %v", err)
		}

		set, err := store.PermissionsOf(ctx, tx, "42")
		if err != nil {
			t.Fatalf("reading a numeric subject's permissions: %v", err)
		}
		if !set.Has("post.create") {
			t.Errorf("the subject holds %v, want post.create", set.Codes())
		}

		// And somebody else holds nothing, so the cast is not making every
		// row match.
		other, err := store.PermissionsOf(ctx, tx, "43")
		if err != nil {
			t.Fatal(err)
		}
		if other.Len() != 0 {
			t.Errorf("subject 43 holds %v, want nothing", other.Codes())
		}

		if err := store.Unassign(ctx, tx, "42", role.ID); err != nil {
			t.Fatalf("unassigning a numeric subject: %v", err)
		}
		set, err = store.PermissionsOf(ctx, tx, "42")
		if err != nil {
			t.Fatal(err)
		}
		if set.Len() != 0 {
			t.Errorf("after unassigning, the subject holds %v", set.Codes())
		}
	})
}
