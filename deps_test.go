package rbac_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The root package is the standard library and nothing else.
//
// It is the package every consumer imports — the catalogue, the permission
// set, the cache key — and those are exactly the things a migration, a
// command-line tool or a test wants to reach without linking a web server or
// a SQL driver. Measured rather than intended, because an import added in
// the wrong file is invisible until somebody profiles a binary.
func TestTheRootPackageIsStandardLibraryOnly(t *testing.T) {
	for _, line := range deps(t, "github.com/lemmego/rbac") {
		// Itself, which go list -deps includes.
		if line == "github.com/lemmego/rbac" {
			continue
		}
		// A standard library import path has no dot in its first segment.
		first, _, _ := strings.Cut(line, "/")
		if strings.Contains(first, ".") {
			t.Errorf("the root package reaches %s; it must stay standard library only", line)
		}
	}
}

// The store reaches the ORM and must NOT reach the framework.
//
// A migration runs this schema and a command-line tool syncs the catalogue
// through it, and neither has any business linking api/app — a migration that
// pulls in a web server is a migration that cannot run in a container built
// to do one job.
func TestTheStoreDoesNotReachTheFramework(t *testing.T) {
	var sawORM bool
	for _, line := range deps(t, "github.com/lemmego/rbac/rbacstore") {
		switch {
		case strings.HasPrefix(line, "github.com/lemmego/api"),
			strings.HasPrefix(line, "github.com/lemmego/authz"),
			strings.HasPrefix(line, "github.com/lemmego/inertia"):
			t.Errorf("the store reaches %s; it must stay framework-free", line)
		case line == "github.com/lemmego/orm":
			sawORM = true
		}
	}
	if !sawORM {
		t.Error("the store does not reach the ORM, so this test is not measuring what it claims")
	}
}

// And the positive half, so the split is measured in both directions rather
// than asserted in one: the authz bridge DOES reach the framework, which is
// the whole reason it is a separate package.
func TestTheAuthzBridgeDoesReachTheFramework(t *testing.T) {
	var sawApp, sawAuthz bool
	for _, line := range deps(t, "github.com/lemmego/rbac/rbacauthz") {
		switch line {
		case "github.com/lemmego/api/app":
			sawApp = true
		case "github.com/lemmego/authz":
			sawAuthz = true
		}
	}
	if !sawApp || !sawAuthz {
		t.Errorf("the authz bridge reaches api/app=%v authz=%v, so this test is not "+
			"measuring what it claims", sawApp, sawAuthz)
	}
	// It must not drag in the database, though: an application that wants
	// permission gates over a store of its own should not link the ORM to
	// get them.
	for _, line := range deps(t, "github.com/lemmego/rbac/rbacauthz") {
		if line == "github.com/lemmego/orm" {
			t.Error("the authz bridge reaches the ORM; the gates read a set from the " +
				"context and have no database in them")
		}
	}
}

func deps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
