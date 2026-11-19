package rbac_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/lemmego/rbac"
)

func TestAWellFormedPermissionIsAccepted(t *testing.T) {
	for _, permission := range []rbac.Permission{
		{Code: "site.create", Module: "site", Description: "Add a site"},
		{Code: "site.view", Module: "site", Description: "See sites"},
		{Code: "payroll.pay_period.unlock", Module: "payroll", Description: "Reopen a locked pay period"},
		{Code: "a.b", Module: "a", Description: "x"},
	} {
		if err := permission.Validate(); err != nil {
			t.Errorf("%q: %v", permission.Code, err)
		}
	}
}

func TestAMalformedPermissionIsRefused(t *testing.T) {
	for name, permission := range map[string]rbac.Permission{
		"no dot":            {Code: "create", Module: "create", Description: "x"},
		"uppercase":         {Code: "Site.create", Module: "Site", Description: "x"},
		"hyphen":            {Code: "site.create-one", Module: "site", Description: "x"},
		"leading dot":       {Code: ".create", Module: "", Description: "x"},
		"trailing dot":      {Code: "site.", Module: "site", Description: "x"},
		"double dot":        {Code: "site..create", Module: "site", Description: "x"},
		"space":             {Code: "site create", Module: "site", Description: "x"},
		"digit first":       {Code: "1site.create", Module: "1site", Description: "x"},
		"empty":             {Code: "", Module: "", Description: "x"},
		"no module":         {Code: "site.create", Module: "", Description: "x"},
		"module disagrees":  {Code: "site.create", Module: "sites", Description: "x"},
		"no description":    {Code: "site.create", Module: "site", Description: ""},
		"blank description": {Code: "site.create", Module: "site", Description: "   "},
	} {
		if err := permission.Validate(); !errors.Is(err, rbac.ErrBadCode) {
			t.Errorf("%s (%q): %v, want ErrBadCode", name, permission.Code, err)
		}
	}
}

func TestACatalogRefusesADuplicate(t *testing.T) {
	catalog := rbac.NewCatalog()
	permission := rbac.Permission{Code: "site.create", Module: "site", Description: "Add a site"}
	if err := catalog.Add(permission); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Add(permission); !errors.Is(err, rbac.ErrDuplicate) {
		t.Fatalf("a duplicate was accepted: %v", err)
	}
	if catalog.Len() != 1 {
		t.Errorf("catalog holds %d, want 1", catalog.Len())
	}
}

// Sorted, so the boot sync, the screen and any test over it agree — and so
// adding a module does not reorder somebody else's output.
func TestACatalogIsSorted(t *testing.T) {
	catalog := rbac.NewCatalog()
	if err := catalog.Add(
		rbac.Permission{Code: "site.view", Module: "site", Description: "x"},
		rbac.Permission{Code: "role.assign", Module: "role", Description: "x"},
		rbac.Permission{Code: "site.create", Module: "site", Description: "x"},
	); err != nil {
		t.Fatal(err)
	}
	want := []string{"role.assign", "site.create", "site.view"}
	got := catalog.Codes()
	if len(got) != len(want) {
		t.Fatalf("codes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("codes = %v, want %v", got, want)
		}
	}
	all := catalog.All()
	for i := range want {
		if all[i].Code != want[i] {
			t.Fatalf("All() = %v, want %v", all, want)
		}
	}
}

// The direction a permission set has to fail.
func TestTheZeroSetGrantsNothing(t *testing.T) {
	var set rbac.Set
	for _, code := range []string{"site.view", "site.create", "", "anything"} {
		if set.Has(code) {
			t.Errorf("the zero set grants %q", code)
		}
	}
	if set.IsEverything() {
		t.Error("the zero set reports itself as the system role")
	}
	if rbac.NewSet().Has("site.view") {
		t.Error("an empty set grants a permission")
	}
}

func TestASetHoldsWhatItWasGiven(t *testing.T) {
	set := rbac.NewSet("site.view", "role.assign")
	if !set.Has("site.view") || !set.Has("role.assign") {
		t.Fatalf("set %v does not hold what it was given", set.Codes())
	}
	if set.Has("site.create") {
		t.Error("the set grants something it was not given")
	}
	if set.Len() != 2 {
		t.Errorf("Len = %d, want 2", set.Len())
	}
}

func TestEverythingGrantsEverything(t *testing.T) {
	set := rbac.Everything()
	for _, code := range []string{"site.view", "payroll.export", "a.b", "not.declared"} {
		if !set.Has(code) {
			t.Errorf("the system role does not grant %q", code)
		}
	}
	if !set.IsEverything() {
		t.Error("Everything() does not report itself as the system role")
	}
	if set.Len() != 0 {
		t.Errorf("the system role holds %d codes, want none — it is a flag, not a list", set.Len())
	}
}

// A cache entry must not be able to conjure the system role, and an entry
// written by an older build must deserialise into a set that grants nothing
// rather than one that grants everything.
func TestASnapshotRoundTripsAndCannotForgeTheSystemRole(t *testing.T) {
	for _, set := range []rbac.Set{
		rbac.NewSet(),
		rbac.NewSet("site.view"),
		rbac.NewSet("site.view", "role.assign"),
		rbac.Everything(),
	} {
		raw, err := json.Marshal(set.Snapshot())
		if err != nil {
			t.Fatal(err)
		}
		var snapshot rbac.Snapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			t.Fatal(err)
		}
		restored := rbac.FromSnapshot(snapshot)
		if restored.IsEverything() != set.IsEverything() {
			t.Errorf("%s: Everything changed across the round trip", raw)
		}
		for _, code := range append(set.Codes(), "site.create", "payroll.export") {
			if restored.Has(code) != set.Has(code) {
				t.Errorf("%s: %q changed across the round trip", raw, code)
			}
		}
	}

	// The shapes an attacker or an old build might leave in the cache.
	for _, raw := range []string{
		`{}`,
		`{"codes":null}`,
		`{"codes":["*"]}`,
		`{"codes":["site.view"]}`,
		`[]`,
	} {
		var snapshot rbac.Snapshot
		if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
			// A shape that does not decode is a miss, which is the right
			// outcome; nothing to assert beyond that it is not everything.
			continue
		}
		if rbac.FromSnapshot(snapshot).IsEverything() {
			t.Errorf("%s deserialised into the system role", raw)
		}
	}

	// And the one value that legitimately does.
	var everything rbac.Snapshot
	if err := json.Unmarshal([]byte(`{"everything":true}`), &everything); err != nil {
		t.Fatal(err)
	}
	if !rbac.FromSnapshot(everything).IsEverything() {
		t.Error("an explicit everything snapshot did not restore the system role")
	}
}

// The cache key carries both identities and a version, so one person's
// permissions cannot be read as another's and an old entry cannot be read as
// a new one.
func TestTheCacheKeyIsSpecific(t *testing.T) {
	a := rbac.CacheKey("ws-1", "7")
	b := rbac.CacheKey("ws-1", "8")
	c := rbac.CacheKey("ws-2", "7")
	if a == b || a == c || b == c {
		t.Fatalf("keys collide: %q %q %q", a, b, c)
	}
	for _, key := range []string{a, b, c} {
		if !contains(key, ":v1") {
			t.Errorf("%q carries no version, so an old entry would be read as a new one", key)
		}
	}
	// Both keys of one scope must carry the same tag, or a flush is half
	// done; two scopes must not, or one flush empties both.
	if rbac.CacheTag("ws-1") == rbac.CacheTag("ws-2") {
		t.Error("two scopes share a cache tag")
	}
}

// A scope and a subject are both opaque, and a subject qualified as
// "user:42" is the normal case — so the key cannot be the two joined by
// something either of them contains.
//
// The pairs below are genuinely different subjects in genuinely different
// scopes. A colon-joined key maps every one of them to one string, and the
// symptom is one tenant's administrator rights handed to another tenant's
// user: the cache answers, so no query runs and nothing is logged.
func TestTheCacheKeyCannotBeConfusedByAColon(t *testing.T) {
	pairs := [][2]string{
		{"acme:eu", "7"},
		{"acme", "eu:7"},
		{"acme", "user:42"},
		{"acme:user", "42"},
		{"", "acme:user:42"},
		{"acme:user:42", ""},
	}

	seen := map[string][2]string{}
	for _, pair := range pairs {
		key := rbac.CacheKey(pair[0], pair[1])
		if other, clash := seen[key]; clash {
			t.Errorf("scope %q subject %q and scope %q subject %q share the key %q",
				pair[0], pair[1], other[0], other[1], key)
			continue
		}
		seen[key] = pair
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
