// Package rbac is the vocabulary of scoped roles and permissions: the
// catalogue of permission codes a build declares, and the set of them one
// subject holds.
//
// It is standard library only, and holds no queries and no cache. That is
// what makes it testable exhaustively without a database — the decisions
// here are "is this code well formed", "does this set contain it" and "what
// is the cache key", and all three are the kind of thing whose bugs are
// invisible in an integration test and obvious in a table.
//
// # A scope is an opaque string
//
// Every role, grant and assignment belongs to a scope, and this package
// never asks what one is. A multi-tenant application passes the tenant id; a
// single-tenant one passes the same constant every time, or "". That is what
// keeps this module independent of any particular notion of tenancy — it
// does not import one, and a tenancy module does not have to know this
// exists.
//
// It is a string rather than a type for the same reason: a named type would
// have to be converted at every boundary, and the thing it would buy —
// stopping a subject id being passed as a scope — is bought instead by the
// two being separate parameters of every function that takes both.
//
// # A subject is an opaque string too
//
// Whoever holds a role: a user, a service account, an API key. A string
// because an application may key its people on an integer, a uuid, or a
// qualified pair like "user:42" when administrators live in a different
// table from customers — and a library that picked one of those would be
// unusable by the applications that picked another.
package rbac

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// DefaultSystemRole is the usual name of the role that means every
// permission.
//
// One per scope, created with it, holding no grants in the database at all.
// Three consequences follow, and each is the reason rather than a side
// effect:
//
//   - it cannot be partially revoked, because there is no grant to delete;
//   - a new module adds nothing to migrate into it;
//   - "who can do everything here" is a membership of one role rather than a
//     set of grants somebody has to keep complete.
//
// Configurable because it is a row in a table and a word in a user
// interface: an application whose product says "owner" or "admin" should not
// have to show its administrators a word this library chose.
const DefaultSystemRole = "superuser"

// CodePattern is the shape of a permission code, as a regular expression.
//
// Exported because the migration that creates the permissions table uses
// this exact string in its CHECK constraint. Two copies of the rule would
// eventually disagree, and the way they would disagree is a code that Go
// accepts and the database refuses — on somebody's deploy, in a migration,
// at the worst possible moment.
const CodePattern = `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`

var codeShape = regexp.MustCompile(CodePattern)

var (
	// ErrBadCode means a permission code is not usable.
	ErrBadCode = errors.New("rbac: unusable permission code")

	// ErrDuplicate means a code was declared twice.
	ErrDuplicate = errors.New("rbac: permission declared twice")
)

// Permission is one thing somebody can be allowed to do.
type Permission struct {
	// Code is "module.action": post.create, invoice.publish, payroll.export.
	//
	// Dotted and module-first so a build can be asked which permissions a
	// module brought, and so a disabled module's codes are identifiable
	// without a second table.
	Code string

	// Module is which part of the system declared it, and must be the first
	// segment of Code — checked rather than assumed, because the two
	// drifting apart is how a module's permissions become unfindable.
	Module string

	// Description is what to show somebody building a role. It is not
	// optional: a permission list with blank rows is a screen nobody can
	// use, and the moment to write the sentence is when the code is
	// declared.
	Description string
}

// Validate reports whether this declaration is usable.
func (p Permission) Validate() error {
	if !codeShape.MatchString(p.Code) {
		return fmt.Errorf("%w: %q — lowercase, dotted, module first, as in \"site.create\"",
			ErrBadCode, p.Code)
	}
	if p.Module == "" {
		return fmt.Errorf("%w: %q declares no module", ErrBadCode, p.Code)
	}
	if prefix, _, _ := strings.Cut(p.Code, "."); prefix != p.Module {
		return fmt.Errorf("%w: %q is declared by module %q, so its first segment should be %q",
			ErrBadCode, p.Code, p.Module, p.Module)
	}
	if strings.TrimSpace(p.Description) == "" {
		return fmt.Errorf("%w: %q has no description, and a permission list with blank "+
			"rows is a screen nobody can use", ErrBadCode, p.Code)
	}
	return nil
}

// Catalog is every permission this build declares.
//
// A value the application builds and hands to the provider, NOT a
// package-level registry filled by init functions. A global registry works
// until a test wants two of them, and then one test's declarations satisfy
// another's assertions — which is a vacuous test that looks like a passing
// one.
type Catalog struct {
	byCode map[string]Permission
	order  []string
}

// NewCatalog returns an empty catalogue.
func NewCatalog() *Catalog {
	return &Catalog{byCode: map[string]Permission{}}
}

// Add declares permissions, refusing anything unusable.
//
// It stops at the first problem and reports it, rather than collecting what
// it can: a malformed declaration is a programming error found at boot, and
// booting with half a catalogue means a gate that denies everybody for a
// reason nobody can see.
func (c *Catalog) Add(permissions ...Permission) error {
	for _, permission := range permissions {
		if err := permission.Validate(); err != nil {
			return err
		}
		if _, exists := c.byCode[permission.Code]; exists {
			return fmt.Errorf("%w: %q", ErrDuplicate, permission.Code)
		}
		c.byCode[permission.Code] = permission
		c.order = append(c.order, permission.Code)
	}
	return nil
}

// Has reports whether a code is declared by this build.
func (c *Catalog) Has(code string) bool {
	_, declared := c.byCode[code]
	return declared
}

// All returns every declared permission, sorted by code.
//
// Sorted rather than in declaration order, so the boot sync, the screen that
// lists them and any test over them agree — and so adding a module does not
// reorder somebody else's output.
func (c *Catalog) All() []Permission {
	all := make([]Permission, 0, len(c.byCode))
	for _, code := range c.order {
		all = append(all, c.byCode[code])
	}
	slices.SortFunc(all, func(a, b Permission) int { return strings.Compare(a.Code, b.Code) })
	return all
}

// Codes returns every declared code, sorted.
func (c *Catalog) Codes() []string {
	codes := make([]string, 0, len(c.byCode))
	for code := range c.byCode {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}

// Len is how many permissions this build declares.
func (c *Catalog) Len() int { return len(c.byCode) }

// Set is the permissions one subject holds in one scope.
//
// Immutable, and the zero value grants NOTHING. That is the direction a
// permission set has to fail: an empty set that meant "no restrictions"
// would turn every failure to load one — a cache miss answered badly, a
// query that errored, a middleware that did not run — into an administrator.
type Set struct {
	codes      map[string]struct{}
	everything bool
}

// NewSet returns a set holding exactly these codes.
func NewSet(codes ...string) Set {
	held := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		held[code] = struct{}{}
	}
	return Set{codes: held}
}

// Everything returns the set a member of the system role holds.
//
// A distinct constructor rather than "a set containing a wildcard code",
// because a wildcard is a string, and a string can arrive from a database
// column, a cache entry or a request. This cannot be forged by data.
func Everything() Set { return Set{everything: true} }

// IsEverything reports whether this is the system role's set.
func (s Set) IsEverything() bool { return s.everything }

// Has reports whether this set grants a code.
func (s Set) Has(code string) bool {
	if s.everything {
		return true
	}
	_, held := s.codes[code]
	return held
}

// Codes returns the granted codes, sorted. Empty for Everything, which holds
// no codes by construction — ask IsEverything.
func (s Set) Codes() []string {
	codes := make([]string, 0, len(s.codes))
	for code := range s.codes {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	return codes
}

// Len is how many codes are held. Zero for Everything.
func (s Set) Len() int { return len(s.codes) }

// Snapshot is the wire form of a Set, for the cache.
//
// A struct with an explicit Everything flag rather than a []string with a
// magic entry, so the system role cannot be conjured by a cache value
// somebody wrote — and so an entry written by an older build deserialises
// into a set that grants nothing rather than one that grants everything.
type Snapshot struct {
	Everything bool     `json:"everything"`
	Codes      []string `json:"codes"`
}

// Snapshot converts a set for storage.
func (s Set) Snapshot() Snapshot {
	return Snapshot{Everything: s.everything, Codes: s.Codes()}
}

// FromSnapshot converts a stored set back.
func FromSnapshot(snapshot Snapshot) Set {
	if snapshot.Everything {
		return Everything()
	}
	return NewSet(snapshot.Codes...)
}

// CacheKey is where one subject's permissions are cached.
//
// Versioned, because the value's shape is this package's and an old entry
// must not be read as a new one. Bump it when Snapshot changes, and every
// stale entry becomes a miss rather than a misreading.
func CacheKey(scope, subject string) string {
	// The scope's length, then the scope, then the subject — because both are
	// opaque strings that may contain a colon, and a subject qualified as
	// "user:42" is the normal case rather than an exotic one.
	//
	// Joining them with a separator either of them can contain collides:
	// CacheKey("acme:eu", "7") and CacheKey("acme", "eu:7") would be the same
	// key, and one tenant's permission set would be served to another
	// tenant's subject. Writing the first field's length makes the key
	// unambiguous whatever is in it, which escaping would also do at the cost
	// of a rule somebody has to remember.
	return "rbac:v1:" + strconv.Itoa(len(scope)) + ":" + scope + ":" + subject
}

// CacheTag is the tag a scope's cached permission sets carry, so a role
// change is one flush rather than a key per subject — nobody knows which
// subjects hold the role that just changed without asking the database, and
// asking it defeats the cache.
//
// An application that caches other per-scope values — enabled features,
// display labels — should pass its own tag to the provider instead, so one
// flush covers all of them and cannot be half done. This is the default for
// an application that has nothing else to invalidate.
func CacheTag(scope string) string { return "rbac:" + scope }

// DefaultPurgeSetting is the transaction-local setting that lets a system
// role be deleted, for the one operation that has to be able to: removing a
// scope entirely.
//
// Explicit and greppable rather than absent, because the alternative is
// worse than a flag. A trigger protects the system role from deletion, and
// every scope has one — so without an escape hatch a scope could never be
// hard-deleted, and the first person who needed to would reach for DROP
// TRIGGER and leave it off.
//
// Transaction-local, so it resets at COMMIT or ROLLBACK and cannot reach the
// next user of a pooled connection.
//
//	SELECT set_config('rbac.purge', 'on', true)
const DefaultPurgeSetting = "rbac.purge"
