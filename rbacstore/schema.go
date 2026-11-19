package rbacstore

import (
	"fmt"
	"strings"

	"github.com/lemmego/rbac"
)

// SchemaConfig is Config plus the things only the DDL needs.
type SchemaConfig struct {
	Config

	// ScopeType is the SQL type of the scope column: text, uuid, bigint.
	// Defaults to text, which is what an opaque scope is.
	ScopeType string

	// SubjectType is the SQL type of the subject column. Defaults to text,
	// for the same reason — and because a qualified subject like "user:42"
	// is a string whatever the underlying key is.
	SubjectType string

	// ScopeReferences is the table and columns the scope column points at,
	// as it would be written after REFERENCES: "tenants (id)".
	//
	// Blank means no foreign key, which is the default: a scope is an opaque
	// string and may not be a row in anything. An application whose scopes
	// ARE rows should set this, because then deleting a tenant cannot leave
	// its roles behind.
	ScopeReferences string

	// SubjectReferences is the same for the subject column, and is
	// COMPOSITE: the referenced table must carry the scope column too, and
	// the reference names both. "users (tenant_id, id)".
	//
	// Blank means no foreign key, and that is the honest default rather than
	// a convenience. A framework cannot know whether subjects live in one
	// table, in three, or outside the database altogether — and a single-
	// column reference to a users table would be WRONG even where one
	// exists: PostgreSQL checks a foreign key with the referenced table's
	// owner rights, which bypasses row-level security, so a non-composite
	// reference will happily accept another scope's user.
	SubjectReferences string

	// PurgeSetting is the transaction-local setting whose value "on" lets the
	// system role be deleted, for the one operation that has to be able to.
	// Defaults to rbac.DefaultPurgeSetting.
	//
	// Whoever removes a scope runs
	//
	//	SELECT set_config(<PurgeSetting>, 'on', true)
	//
	// in the same transaction as the delete.
	PurgeSetting string

	// Prefix is prepended to the names of the functions and triggers this
	// schema creates, so two installations in one database do not collide.
	// Defaults to "rbac".
	Prefix string
}

// WithDefaults fills in whatever was left blank.
func (c SchemaConfig) WithDefaults() SchemaConfig {
	c.Config = c.Config.WithDefaults()
	if c.ScopeType == "" {
		c.ScopeType = "text"
	}
	if c.SubjectType == "" {
		c.SubjectType = "text"
	}
	if c.Prefix == "" {
		c.Prefix = "rbac"
	}
	if c.PurgeSetting == "" {
		c.PurgeSetting = rbac.DefaultPurgeSetting
	}
	return c
}

// SchemaStatements is the DDL for this schema, in order.
//
// PostgreSQL. Three of the things in here are not portable and are not
// incidental: a partial unique index, so a soft-deleted role's name is free
// again; plpgsql triggers, because the system role's protection has to hold
// against anything that writes the table and not only against this package;
// and ON CONFLICT, which the store's idempotent writes rely on.
//
// Returned as statements rather than run, so it is the application's
// migration — the application's to read, to review, to edit and to roll
// back, and findable in whatever table its migrator records. A library that
// created its own tables at boot would put tables in somebody's database
// that nothing in their project mentions.
func SchemaStatements(cfg SchemaConfig) []string {
	cfg = cfg.WithDefaults()
	c := cfg.Config
	scope, subject := c.ScopeColumn, c.SubjectColumn
	roles, grants, assignments, permissions :=
		c.RolesTable, c.GrantsTable, c.AssignmentsTable, c.PermissionsTable

	scopeRef, subjectRef := "", ""
	if cfg.ScopeReferences != "" {
		scopeRef = " REFERENCES " + cfg.ScopeReferences + " ON DELETE RESTRICT"
	}
	if cfg.SubjectReferences != "" {
		subjectRef = ",\n\t\t\t  FOREIGN KEY (" + scope + ", " + subject + ")\n" +
			"\t\t\t    REFERENCES " + cfg.SubjectReferences + " ON DELETE CASCADE"
	}

	return []string{
		// A permission is a fact about the software, so this table is not
		// scoped: the same code means the same thing in every scope.
		`CREATE TABLE ` + permissions + ` (
			code        text        PRIMARY KEY,
			module      text        NOT NULL,
			description text        NOT NULL,
			created_at  timestamptz NOT NULL DEFAULT now(),
			updated_at  timestamptz NOT NULL DEFAULT now()
		)`,

		// The shape rule, as the same string Go checks. Two copies of it
		// would eventually disagree, and the way they would disagree is a
		// code Go accepts and the database refuses — in a migration, on
		// somebody's deploy.
		`ALTER TABLE ` + permissions + ` ADD CONSTRAINT ` + permissions + `_code_shape
		   CHECK (code ~ '` + rbac.CodePattern + `')`,

		`CREATE INDEX ` + permissions + `_module ON ` + permissions + ` (module, code)`,

		`CREATE TABLE ` + roles + ` (
			id          bigserial   PRIMARY KEY,
			` + scope + ` ` + cfg.ScopeType + ` NOT NULL` + scopeRef + `,
			name        text        NOT NULL,
			description text        NOT NULL DEFAULT '',
			is_system   boolean     NOT NULL DEFAULT false,
			created_at  timestamptz NOT NULL DEFAULT now(),
			updated_at  timestamptz NOT NULL DEFAULT now(),
			deleted_at  timestamptz
		)`,

		// The composite key the pivots reference. Without it their foreign
		// keys could only name roles.id, and a grant could then point at
		// another scope's role.
		`ALTER TABLE ` + roles + ` ADD CONSTRAINT ` + roles + `_scope_key
		   UNIQUE (` + scope + `, id)`,

		// Partial, so a soft-deleted role's name is available again. A plain
		// unique index would mean deleting a role reserved its name forever.
		`CREATE UNIQUE INDEX ` + roles + `_scope_name_live
		   ON ` + roles + ` (` + scope + `, lower(name)) WHERE deleted_at IS NULL`,

		// One system role per scope, and the database is what says so.
		`CREATE UNIQUE INDEX ` + roles + `_one_system
		   ON ` + roles + ` (` + scope + `) WHERE is_system AND deleted_at IS NULL`,

		`CREATE TABLE ` + grants + ` (
			` + scope + ` ` + cfg.ScopeType + ` NOT NULL,
			role_id         bigint NOT NULL,
			permission_code text   NOT NULL REFERENCES ` + permissions + ` (code) ON DELETE CASCADE,
			created_at      timestamptz NOT NULL DEFAULT now(),
			PRIMARY KEY (` + scope + `, role_id, permission_code),
			FOREIGN KEY (` + scope + `, role_id)
			  REFERENCES ` + roles + ` (` + scope + `, id) ON DELETE CASCADE
		)`,

		`CREATE INDEX ` + grants + `_code ON ` + grants + ` (permission_code)`,

		`CREATE TABLE ` + assignments + ` (
			` + scope + ` ` + cfg.ScopeType + ` NOT NULL,
			` + subject + ` ` + cfg.SubjectType + ` NOT NULL,
			role_id    bigint NOT NULL,
			created_at timestamptz NOT NULL DEFAULT now(),
			PRIMARY KEY (` + scope + `, ` + subject + `, role_id),
			FOREIGN KEY (` + scope + `, role_id)
			  REFERENCES ` + roles + ` (` + scope + `, id) ON DELETE CASCADE` + subjectRef + `
		)`,

		// The reverse lookup: who holds this role. Asked by every screen
		// that lists a role's members.
		`CREATE INDEX ` + assignments + `_role
		   ON ` + assignments + ` (` + scope + `, role_id, ` + subject + `)`,

		// The system role holds no grants at all, and this is what makes
		// that true rather than conventional. Granting into it would create
		// a role that is "everything" in code and a list of codes in the
		// database — and then revoking one would appear to work and change
		// nothing.
		`CREATE FUNCTION ` + cfg.Prefix + `_refuse_system_grant() RETURNS trigger AS $$
		 BEGIN
		   IF EXISTS (SELECT 1 FROM ` + roles + ` r
		               WHERE r.` + scope + ` = NEW.` + scope + `
		                 AND r.id = NEW.role_id
		                 AND r.is_system) THEN
		     RAISE EXCEPTION 'the system role holds every permission, so it cannot be granted one';
		   END IF;
		   RETURN NEW;
		 END $$ LANGUAGE plpgsql`,

		`CREATE TRIGGER ` + grants + `_refuse_system
		   BEFORE INSERT OR UPDATE ON ` + grants + `
		   FOR EACH ROW EXECUTE FUNCTION ` + cfg.Prefix + `_refuse_system_grant()`,

		// And it cannot be renamed, demoted or deleted — except by the one
		// operation that must be able to, which is removing a scope
		// entirely.
		`CREATE FUNCTION ` + cfg.Prefix + `_protect_system_role() RETURNS trigger AS $$
		 BEGIN
		   -- The escape hatch, transaction-local so it cannot reach the next
		   -- user of a pooled connection. Without it a scope could never be
		   -- hard-deleted, and whoever first needed to would reach for DROP
		   -- TRIGGER and leave it off.
		   IF coalesce(current_setting('` + cfg.PurgeSetting + `', true), '') = 'on' THEN
		     IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
		     RETURN NEW;
		   END IF;
		   IF TG_OP = 'DELETE' THEN
		     IF OLD.is_system THEN
		       RAISE EXCEPTION 'a system role cannot be deleted; a scope purge sets % first',
		         '` + cfg.PurgeSetting + `';
		     END IF;
		     RETURN OLD;
		   END IF;
		   IF OLD.is_system AND (NEW.name <> OLD.name
		                         OR NEW.is_system <> OLD.is_system
		                         OR NEW.deleted_at IS NOT NULL) THEN
		     RAISE EXCEPTION 'a system role cannot be renamed, demoted or deleted';
		   END IF;
		   RETURN NEW;
		 END $$ LANGUAGE plpgsql`,

		`CREATE TRIGGER ` + roles + `_protect_system
		   BEFORE UPDATE OR DELETE ON ` + roles + `
		   FOR EACH ROW EXECUTE FUNCTION ` + cfg.Prefix + `_protect_system_role()`,
	}
}

// DropStatements undoes SchemaStatements, in reverse order.
func DropStatements(cfg SchemaConfig) []string {
	cfg = cfg.WithDefaults()
	c := cfg.Config
	return []string{
		`DROP TRIGGER IF EXISTS ` + c.RolesTable + `_protect_system ON ` + c.RolesTable,
		`DROP FUNCTION IF EXISTS ` + cfg.Prefix + `_protect_system_role()`,
		`DROP TRIGGER IF EXISTS ` + c.GrantsTable + `_refuse_system ON ` + c.GrantsTable,
		`DROP FUNCTION IF EXISTS ` + cfg.Prefix + `_refuse_system_grant()`,
		`DROP TABLE IF EXISTS ` + c.AssignmentsTable,
		`DROP TABLE IF EXISTS ` + c.GrantsTable,
		`DROP TABLE IF EXISTS ` + c.RolesTable,
		`DROP TABLE IF EXISTS ` + c.PermissionsTable,
	}
}

// CreateSystemRole is the statement that gives a new scope its system role.
//
// Not part of SchemaStatements, because it runs once per scope rather than
// once per database — whoever creates a scope runs this in the same
// transaction. A scope without one is a scope nobody can administer.
func CreateSystemRole(cfg Config) string {
	cfg = cfg.WithDefaults()
	return `INSERT INTO ` + cfg.RolesTable + ` (` + cfg.ScopeColumn + `, name, description, is_system)
	        VALUES ($1, '` + strings.ReplaceAll(cfg.SystemRole, "'", "''") + `',
	                'Every permission, including those added later', true)
	        RETURNING id`
}

// String renders the schema as one script, for a migration file or for
// reading.
func Script(cfg SchemaConfig) string {
	statements := SchemaStatements(cfg)
	var out strings.Builder
	for i, statement := range statements {
		if i > 0 {
			out.WriteString(";\n\n")
		}
		out.WriteString(fmt.Sprint(statement))
	}
	out.WriteString(";\n")
	return out.String()
}
