// Package rbacstore reads and writes roles, grants and assignments.
//
// # Every method takes the request's transaction, and the scope comes off it
//
// Not a database handle, and not a scope parameter. The scope is resolved
// from the handle — Config.ScopeOf, which by default reads the tenant the
// ORM transaction is bound to — so there is no spelling of any of these
// calls that could name a scope other than the one the caller is in. A scope
// parameter would be one more thing a caller could get wrong, in the one
// place where getting it wrong is a cross-tenant write.
//
// # These queries are raw, and that is a decision rather than laziness
//
// Raw SQL carries no implicit tenant predicate — there is no way to inject
// one into hand-written SQL, which is precisely why row-level security
// exists. So these statements are protected by ONE layer rather than two
// where an application has two, and the isolation test for them is therefore
// a test of the database's policies specifically. Every statement below also
// names the scope column explicitly, both because the pivots' primary keys
// lead with it (a join that omitted it could not use the index) and so that
// each statement is correct on its own terms.
//
// # Table and column names come from Config and nowhere else
//
// They are interpolated into the statements once, in New, because a
// placeholder cannot carry an identifier in any SQL dialect. Nothing from a
// request ever reaches that interpolation: the values are an application's
// own schema, fixed at boot. Everything that varies per call — the scope,
// the subject, a role id, a permission code — is bound.
package rbacstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/lemmego/orm"

	"github.com/lemmego/rbac"
)

// Defaults for Config. An application whose schema already spells these
// differently configures them rather than migrating.
const (
	DefaultRolesTable       = "roles"
	DefaultGrantsTable      = "role_permissions"
	DefaultAssignmentsTable = "user_roles"
	DefaultPermissionsTable = "permissions"
	DefaultScopeColumn      = "scope"
	DefaultSubjectColumn    = "subject"
)

var (
	// ErrNoScope means ScopeOf could not answer, so nothing can be read or
	// written. It is an error rather than an empty scope deliberately: an
	// empty scope is a legitimate value for a single-tenant application, so
	// treating "I could not tell" as "" would hand one application's answer
	// to another's question.
	ErrNoScope = errors.New("rbacstore: the transaction names no scope")

	// ErrSystemRole means an operation would have changed a scope's system
	// role. The database refuses it too; this is the readable half.
	ErrSystemRole = errors.New("rbacstore: the system role cannot be changed")

	// ErrNoRole means no such role in this scope.
	ErrNoRole = errors.New("rbacstore: no such role")

	// ErrNotMigrated means the permissions table does not exist yet, which
	// is the normal state of a database the migrations have not run against.
	//
	// Named rather than returned as a driver error, so a provider can treat
	// "not migrated yet" as a warning and boot — otherwise the command that
	// runs the migrations cannot start, which is a deadlock a fresh install
	// hits on its first command.
	ErrNotMigrated = errors.New("rbacstore: the permissions table does not exist")
)

// Role is a role of one scope.
type Role struct {
	ID          int64  `db:"id"`
	Name        string `db:"name"`
	Description string `db:"description"`
	IsSystem    bool   `db:"is_system"`
}

// ScopeFromTenant reads the scope off the ORM handle's tenant binding, which
// is what a multi-tenant application wants and is the default.
//
// It reads an ORM concept rather than a tenancy module's, so this package
// depends on no notion of tenancy and a single-tenant application can
// replace it with Unscoped.
func ScopeFromTenant(tx *orm.Tx) (string, error) {
	value, bound := tx.TenantValue()
	if !bound {
		return "", ErrNoScope
	}
	switch scope := value.(type) {
	case string:
		if scope == "" {
			return "", ErrNoScope
		}
		return scope, nil
	case fmt.Stringer:
		return scope.String(), nil
	}
	return fmt.Sprint(value), nil
}

// Unscoped answers the same scope for every transaction, for an application
// that has one.
//
// Pass Unscoped("") for a schema whose scope column is empty throughout, or
// a constant like Unscoped("default") if the column is NOT NULL and you
// would rather read a word than a blank in a row.
func Unscoped(scope string) func(*orm.Tx) (string, error) {
	return func(*orm.Tx) (string, error) { return scope, nil }
}

// Config is the schema this store reads, and how it finds the scope.
type Config struct {
	RolesTable       string
	GrantsTable      string
	AssignmentsTable string
	PermissionsTable string

	// ScopeColumn is the column every role, grant and assignment carries.
	ScopeColumn string

	// SubjectColumn is the column in the assignments table that holds whoever
	// holds the role.
	SubjectColumn string

	// SystemRole is the name of the all-permissions role.
	SystemRole string

	// ScopeOf resolves the scope from the handle.
	//
	// Defaults to ScopeFromTenant, and that direction is deliberate. The
	// alternative default — one scope for everybody — would mean a
	// multi-tenant application that forgot to configure this shares one set
	// of roles across every tenant, silently and with every test passing. A
	// single-tenant application that has not configured it instead gets
	// ErrNoScope on its first call, which is a boot-time error somebody
	// reads.
	ScopeOf func(*orm.Tx) (string, error)
}

// WithDefaults fills in whatever was left blank.
func (c Config) WithDefaults() Config {
	if c.RolesTable == "" {
		c.RolesTable = DefaultRolesTable
	}
	if c.GrantsTable == "" {
		c.GrantsTable = DefaultGrantsTable
	}
	if c.AssignmentsTable == "" {
		c.AssignmentsTable = DefaultAssignmentsTable
	}
	if c.PermissionsTable == "" {
		c.PermissionsTable = DefaultPermissionsTable
	}
	if c.ScopeColumn == "" {
		c.ScopeColumn = DefaultScopeColumn
	}
	if c.SubjectColumn == "" {
		c.SubjectColumn = DefaultSubjectColumn
	}
	if c.SystemRole == "" {
		c.SystemRole = rbac.DefaultSystemRole
	}
	if c.ScopeOf == nil {
		c.ScopeOf = ScopeFromTenant
	}
	return c
}

// Store reads and writes one schema's roles.
type Store struct {
	cfg Config

	permissionsOf string
	roles         string
	grants        string
	createRole    string
	deleteRole    string
	grant         string
	revoke        string
	assign        string
	unassign      string
	roleNamed     string
}

// New returns a store over this schema.
func New(cfg Config) *Store {
	cfg = cfg.WithDefaults()
	s := &Store{cfg: cfg}

	scope, subject := cfg.ScopeColumn, cfg.SubjectColumn
	roles, grants, assignments := cfg.RolesTable, cfg.GrantsTable, cfg.AssignmentsTable

	s.permissionsOf = `
		SELECT r.is_system, rp.permission_code
		  FROM ` + assignments + ` ur
		  JOIN ` + roles + ` r
		    ON r.` + scope + ` = ur.` + scope + ` AND r.id = ur.role_id
		  LEFT JOIN ` + grants + ` rp
		    ON rp.` + scope + ` = r.` + scope + ` AND rp.role_id = r.id
		 WHERE ur.` + scope + ` = $1 AND ur.` + subject + ` = $2
		   AND r.deleted_at IS NULL`

	s.roles = `
		SELECT id, name, description, is_system
		  FROM ` + roles + `
		 WHERE ` + scope + ` = $1 AND deleted_at IS NULL
		 ORDER BY is_system DESC, lower(name)`

	s.grants = `
		SELECT permission_code
		  FROM ` + grants + `
		 WHERE ` + scope + ` = $1 AND role_id = $2
		 ORDER BY permission_code`

	s.createRole = `
		INSERT INTO ` + roles + ` (` + scope + `, name, description, is_system)
		VALUES ($1, $2, $3, false)
		RETURNING id, name, description, is_system`

	s.deleteRole = `
		UPDATE ` + roles + ` SET deleted_at = now()
		 WHERE ` + scope + ` = $1 AND id = $2 AND deleted_at IS NULL`

	s.grant = `
		INSERT INTO ` + grants + ` (` + scope + `, role_id, permission_code)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`

	s.revoke = `
		DELETE FROM ` + grants + `
		 WHERE ` + scope + ` = $1 AND role_id = $2 AND permission_code = $3`

	s.assign = `
		INSERT INTO ` + assignments + ` (` + scope + `, ` + subject + `, role_id)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`

	s.unassign = `
		DELETE FROM ` + assignments + `
		 WHERE ` + scope + ` = $1 AND ` + subject + ` = $2 AND role_id = $3`

	s.roleNamed = `
		SELECT id, name, description, is_system
		  FROM ` + roles + `
		 WHERE ` + scope + ` = $1 AND lower(name) = lower($2) AND deleted_at IS NULL`

	return s
}

// Config returns the configuration in force, defaults filled in.
func (s *Store) Config() Config { return s.cfg }

type permissionRow struct {
	IsSystem bool    `db:"is_system"`
	Code     *string `db:"permission_code"`
}

// PermissionsOf is every permission one subject holds in this scope.
//
// One query rather than role-then-grants, because this runs on every request
// that checks anything. The LEFT JOIN matters: the system role holds no
// grants at all, so an inner join would return no rows for the one subject
// who is allowed everything — and the answer would be an empty set, which
// denies.
func (s *Store) PermissionsOf(ctx context.Context, tx *orm.Tx, subject string) (rbac.Set, error) {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return rbac.Set{}, err
	}

	rows, err := tx.Raw[permissionRow](s.permissionsOf, scope, subject).All(ctx)
	if err != nil {
		return rbac.Set{}, fmt.Errorf("rbacstore: reading permissions: %w", err)
	}

	codes := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.IsSystem {
			return rbac.Everything(), nil
		}
		if row.Code != nil {
			codes = append(codes, *row.Code)
		}
	}
	return rbac.NewSet(codes...), nil
}

// Roles lists this scope's roles, the system role first and then by name.
func (s *Store) Roles(ctx context.Context, tx *orm.Tx) ([]Role, error) {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return nil, err
	}
	return tx.Raw[Role](s.roles, scope).All(ctx)
}

// Grants lists the permission codes one role holds.
func (s *Store) Grants(ctx context.Context, tx *orm.Tx, roleID int64) ([]string, error) {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return nil, err
	}
	type row struct {
		Code string `db:"permission_code"`
	}
	rows, err := tx.Raw[row](s.grants, scope, roleID).All(ctx)
	if err != nil {
		return nil, err
	}
	codes := make([]string, 0, len(rows))
	for _, r := range rows {
		codes = append(codes, r.Code)
	}
	return codes, nil
}

// CreateRole adds an ordinary role.
//
// is_system is written false here and is not a parameter: a scope gets
// exactly one system role, when it is created, and the database refuses a
// second. Making it an argument would invite somebody to pass true.
func (s *Store) CreateRole(ctx context.Context, tx *orm.Tx, name, description string) (Role, error) {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return Role{}, err
	}
	role, err := tx.Raw[Role](s.createRole, scope, name, description).First(ctx)
	if err != nil {
		return Role{}, fmt.Errorf("rbacstore: creating role %q: %w", name, err)
	}
	return *role, nil
}

// DeleteRole soft-deletes an ordinary role. A trigger refuses the system
// role; this reports the refusal rather than relying on it.
func (s *Store) DeleteRole(ctx context.Context, tx *orm.Tx, roleID int64) error {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return err
	}
	result, err := tx.Exec(ctx, s.deleteRole, scope, roleID)
	if err != nil {
		return fmt.Errorf("rbacstore: deleting role %d: %w", roleID, err)
	}
	return affectedOne(result, roleID)
}

// Grant adds a permission to a role. Idempotent.
func (s *Store) Grant(ctx context.Context, tx *orm.Tx, roleID int64, code string) error {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, s.grant, scope, roleID, code); err != nil {
		return fmt.Errorf("rbacstore: granting %s to role %d: %w", code, roleID, err)
	}
	return nil
}

// Revoke removes a permission from a role. Idempotent.
func (s *Store) Revoke(ctx context.Context, tx *orm.Tx, roleID int64, code string) error {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, s.revoke, scope, roleID, code); err != nil {
		return fmt.Errorf("rbacstore: revoking %s from role %d: %w", code, roleID, err)
	}
	return nil
}

// Assign gives a subject a role. Idempotent.
func (s *Store) Assign(ctx context.Context, tx *orm.Tx, subject string, roleID int64) error {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, s.assign, scope, subject, roleID); err != nil {
		return fmt.Errorf("rbacstore: assigning role %d: %w", roleID, err)
	}
	return nil
}

// Unassign takes a role away. Idempotent.
func (s *Store) Unassign(ctx context.Context, tx *orm.Tx, subject string, roleID int64) error {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, s.unassign, scope, subject, roleID); err != nil {
		return fmt.Errorf("rbacstore: unassigning role %d: %w", roleID, err)
	}
	return nil
}

// RoleNamed resolves a role by name within this scope.
func (s *Store) RoleNamed(ctx context.Context, tx *orm.Tx, name string) (Role, error) {
	scope, err := s.cfg.ScopeOf(tx)
	if err != nil {
		return Role{}, err
	}
	role, err := tx.Raw[Role](s.roleNamed, scope, name).First(ctx)
	if errors.Is(err, orm.ErrNotFound) {
		return Role{}, fmt.Errorf("%w: %q", ErrNoRole, name)
	}
	if err != nil {
		return Role{}, err
	}
	return *role, nil
}

func affectedOne(result interface{ RowsAffected() (int64, error) }, roleID int64) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("%w: %d", ErrNoRole, roleID)
	}
	return nil
}

// SyncPermissions writes the catalogue this build declares into the
// permissions table.
//
// # It never deletes
//
// A code that is in the table and not in the catalogue is left alone, and
// that is required rather than cautious: modules are compiled selectively,
// so a build without one module would otherwise delete every permission that
// module declared — cascading to every grant that referenced one — and a
// later build with the module back would find the roles silently emptied.
// Deleting a permission is a migration somebody writes deliberately, with
// the grants in front of them.
//
// Unscoped on purpose: permissions is a global table, because a code is a
// fact about the software rather than about a scope.
func (s *Store) SyncPermissions(ctx context.Context, db *orm.DB, catalog *rbac.Catalog) (int, error) {
	all := catalog.All()
	if len(all) == 0 {
		return 0, nil
	}

	// Asked rather than inferred from a failed INSERT.
	//
	// The alternative is matching a driver error code, which means this
	// package learns which driver it is behind — and the distinction being
	// drawn is "has this database been migrated", which is a question with a
	// direct answer.
	var migrated bool
	if err := db.SQLDB().QueryRowContext(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM information_schema.tables
		   WHERE table_name = $1)`, s.cfg.PermissionsTable).Scan(&migrated); err != nil {
		return 0, fmt.Errorf("rbacstore: checking for the %s table: %w", s.cfg.PermissionsTable, err)
	}
	if !migrated {
		return 0, ErrNotMigrated
	}

	tx, err := db.SQLDB().BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("rbacstore: syncing permissions: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	upsert := `
		INSERT INTO ` + s.cfg.PermissionsTable + ` (code, module, description)
		VALUES ($1, $2, $3)
		ON CONFLICT (code) DO UPDATE
		   SET module = excluded.module,
		       description = excluded.description,
		       updated_at = now()`

	for _, permission := range all {
		// Validated again here rather than trusted. The catalogue checks on
		// Add, but this is the boundary where a bad code becomes a CHECK
		// violation inside a transaction at boot, and the message the
		// database gives is not the one that says what to fix.
		if err := permission.Validate(); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, upsert,
			permission.Code, permission.Module, permission.Description); err != nil {
			return 0, fmt.Errorf("rbacstore: syncing %s: %w", permission.Code, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("rbacstore: committing the permission sync: %w", err)
	}
	return len(all), nil
}
