package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBootstrapIsAdmin(t *testing.T) {
	store, err := Load("secret", "")
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := store.Lookup("secret")
	if !ok {
		t.Fatal("bootstrap key missing")
	}
	if principal.ID != BootstrapID || !principal.AllowsWrite() || !principal.AllowsRead() {
		t.Fatalf("principal = %+v", principal)
	}
	for _, source := range []string{SourceBuiltin, SourceNuclei, SourceTeam, SourceCustom} {
		if !principal.AllowsSource(source) {
			t.Fatalf("bootstrap cannot see %s", source)
		}
	}
}

func TestLoadKeysFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`[
		{"id":"public-mcp","key":"pub","sources":["builtin"],"access":"read"},
		{"id":"pojun-agent","key":"agent","sources":["builtin","team"],"access":"read"},
		{"id":"ops","key":"ops","sources":["builtin","team","custom"],"access":"write"}
	]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Load("admin", path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Count() != 4 {
		t.Fatalf("count = %d, want 4", store.Count())
	}
	pub, _ := store.Lookup("pub")
	if pub.AllowsSource(SourceTeam) || pub.AllowsWrite() || !pub.AllowsSource(SourceNuclei) {
		t.Fatalf("public principal = %+v sources=%v", pub, pub.Sources)
	}
	agent, _ := store.Lookup("agent")
	if !agent.AllowsSource(SourceTeam) || agent.AllowsCustomWrite() {
		t.Fatalf("agent principal = %+v", agent)
	}
	ops, _ := store.Lookup("ops")
	if !ops.AllowsCustomWrite() || !ops.AllowsToggle(SourceTeam) {
		t.Fatalf("ops principal = %+v", ops)
	}
}

func TestLoadRejectsDuplicateAndUnknown(t *testing.T) {
	dir := t.TempDir()
	dupKey := filepath.Join(dir, "dup-key.json")
	if err := os.WriteFile(dupKey, []byte(`[{"id":"other","key":"admin","sources":["builtin"],"access":"read"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("admin", dupKey); err == nil {
		t.Fatal("duplicate key accepted")
	}
	unknown := filepath.Join(dir, "unknown.json")
	if err := os.WriteFile(unknown, []byte(`[{"id":"x","key":"k","sources":["nuclei"],"access":"read"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("", unknown); err == nil {
		t.Fatal("direct nuclei grant accepted")
	}
}

func TestFromContextDefaultsToAdmin(t *testing.T) {
	principal := FromContext(t.Context())
	if !principal.AllowsSource(SourceTeam) || !principal.AllowsWrite() {
		t.Fatalf("default principal = %+v", principal)
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := Load("", filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing keys file accepted")
	}
}

func TestStoreIDsOmitsKeys(t *testing.T) {
	store, err := Load("secret", "")
	if err != nil {
		t.Fatal(err)
	}
	ids := store.IDs()
	if len(ids) != 1 || ids[0] != BootstrapID {
		t.Fatalf("ids = %v", ids)
	}
	for _, id := range ids {
		if id == "secret" {
			t.Fatal("key leaked in ids")
		}
	}
}

func TestRequireIndependentAdminKey(t *testing.T) {
	store, err := Load("secret", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireIndependentAdminKey(store, "secret"); err == nil {
		t.Fatal("reused MCP key accepted as admin key")
	}
	if err := RequireIndependentAdminKey(store, "console-secret"); err != nil {
		t.Fatal(err)
	}
	if err := RequireIndependentAdminKey(store, ""); err != nil {
		t.Fatal(err)
	}
}

func TestPublicPrincipalsOmitsKeys(t *testing.T) {
	store, err := Load("secret", "")
	if err != nil {
		t.Fatal(err)
	}
	got := store.PublicPrincipals()
	if len(got) != 1 || got[0].ID != BootstrapID || got[0].Access[0] != AccessRead || got[0].Access[1] != AccessWrite {
		t.Fatalf("principals = %+v", got)
	}
}

func TestOpenOptionalMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store, err := Open("admin", path, true)
	if err != nil {
		t.Fatal(err)
	}
	if store.Count() != 1 {
		t.Fatalf("count = %d", store.Count())
	}
}

func TestCreateUpdateRotateDeletePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "keys.json")
	store, err := Open("admin", path, true)
	if err != nil {
		t.Fatal(err)
	}

	created, key, err := store.Create(KeyInput{
		ID:      "public-mcp",
		Access:  json.RawMessage(`["read"]`),
		Sources: []string{"builtin"},
	}, "console-key")
	if err != nil {
		t.Fatal(err)
	}
	if created.Origin != OriginFile || key == "" || key == "admin" {
		t.Fatalf("created = %+v key=%q", created, key)
	}
	if _, ok := store.Lookup(key); !ok {
		t.Fatal("created key not live")
	}

	updated, err := store.Update("public-mcp", json.RawMessage(`["read","write"]`), []string{"builtin", "team", "custom"})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Access) != 2 || updated.Access[1] != AccessWrite || len(updated.Sources) != 3 {
		t.Fatalf("updated = %+v", updated)
	}
	live, _ := store.Lookup(key)
	if !live.AllowsCustomWrite() {
		t.Fatalf("live principal = %+v", live)
	}

	rotated, newKey, err := store.Rotate("public-mcp", "console-key")
	if err != nil {
		t.Fatal(err)
	}
	if newKey == key {
		t.Fatal("rotate kept old key")
	}
	if _, ok := store.Lookup(key); ok {
		t.Fatal("old key still live")
	}
	if _, ok := store.Lookup(newKey); !ok || rotated.ID != "public-mcp" {
		t.Fatalf("rotated = %+v newKey live=%v", rotated, ok)
	}

	if err := store.Delete("public-mcp"); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Lookup(newKey); ok {
		t.Fatal("deleted key still live")
	}

	reloaded, err := Load("admin", path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Count() != 1 {
		t.Fatalf("reloaded count = %d", reloaded.Count())
	}
}

func TestCannotMutateBootstrap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store, err := Open("admin", path, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(BootstrapID, json.RawMessage(`["read"]`), []string{"builtin"}); err == nil {
		t.Fatal("bootstrap update accepted")
	}
	if _, _, err := store.Rotate(BootstrapID, "console-key"); err == nil {
		t.Fatal("bootstrap rotate accepted")
	}
	if err := store.Delete(BootstrapID); err == nil {
		t.Fatal("bootstrap delete accepted")
	}
}

func TestCreateRejectsReservedAndAdminKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store, err := Open("", path, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Create(KeyInput{ID: BootstrapID, Access: json.RawMessage(`["read"]`), Sources: []string{"builtin"}}, "console-key"); err == nil {
		t.Fatal("reserved id accepted")
	}
	if _, _, err := store.Create(KeyInput{ID: "ops", Key: "console-key", Access: json.RawMessage(`["read"]`), Sources: []string{"builtin"}}, "console-key"); err == nil {
		t.Fatal("admin key reuse accepted")
	}
}

func TestCreateRejectsDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store, err := Open("admin", path, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Create(KeyInput{ID: "ops", Key: "ops-key", Access: json.RawMessage(`["read"]`), Sources: []string{"builtin"}}, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Create(KeyInput{ID: "ops", Key: "other", Access: json.RawMessage(`["read"]`), Sources: []string{"builtin"}}, ""); err == nil {
		t.Fatal("duplicate id accepted")
	}
	if _, _, err := store.Create(KeyInput{ID: "other", Key: "ops-key", Access: json.RawMessage(`["read"]`), Sources: []string{"builtin"}}, ""); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestLegacyWriteAccessStillReads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(path, []byte(`[{"id":"ops","key":"ops","sources":["builtin"],"access":"write"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Load("", path)
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := store.Lookup("ops")
	if !ok || !principal.AllowsRead() || !principal.AllowsWrite() {
		t.Fatalf("legacy write principal = %+v ok=%v", principal, ok)
	}
}

func TestExplicitWriteOnlyDoesNotRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	store, err := Open("", path, true)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := store.Create(KeyInput{
		ID:      "writer",
		Access:  json.RawMessage(`["write"]`),
		Sources: []string{"builtin", "custom"},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	principal, ok := store.Lookup(key)
	if !ok || principal.AllowsRead() || !principal.AllowsWrite() {
		t.Fatalf("write-only principal = %+v", principal)
	}

	reloaded, err := Load("", path)
	if err != nil {
		t.Fatal(err)
	}
	principal, ok = reloaded.Lookup(key)
	if !ok || principal.AllowsRead() || !principal.AllowsWrite() {
		t.Fatalf("reloaded write-only principal = %+v", principal)
	}
}
