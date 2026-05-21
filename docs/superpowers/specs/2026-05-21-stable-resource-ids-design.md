# Stable Resource IDs Design

## Context

context1337 currently returns resources by `name`, `type`, and for files by `path`. That works for simple single-source lookups, but it becomes ambiguous when multiple sources contain the same resource name, such as `builtin` and `nuclei` both providing `CVE-2021-44228`. It also forces MCP clients to preserve several lookup shapes: `name/type` for skills and vulnerabilities, `path/type` for dictionaries and payloads.

This design adds stable resource IDs inspired by context7's stable library IDs. Search results will include an ID that can be passed back to detail/file tools without the model reconstructing lookup parameters. The first version computes IDs from existing fields at runtime and avoids database schema changes.

## Goals

- Add deterministic, stable IDs to MCP search/list results.
- Let `get_security_detail` and `read_security_file` accept those IDs directly.
- Preserve existing `name/type/path` inputs for backward compatibility.
- Detect and reject mismatches when callers provide both an `id` and conflicting legacy parameters.
- Prove the value with repeated correctness tests and Agent-style ambiguity tests.

## Non-goals

- No SQLite schema migration.
- No builtin database rebuild requirement just for IDs.
- No source-version pinning in the first version.
- No chunk-level retrieval or `topic/tokens` retrieval in this change.

## ID Format

Use URI-style IDs:

```text
absec://{source}/{type}/{escaped-key}
```

Where:

- `source` is the resource source, such as `builtin`, `team`, or `nuclei`.
- `type` is one of `skill`, `dict`, `payload`, or `vuln`.
- `key` is:
  - resource `name` for `skill` and `vuln`
  - resource path/name for `dict` and `payload`
- `escaped-key` uses URL path escaping so file paths and special characters remain parseable.

Examples:

```text
absec://builtin/skill/sql-injection
absec://team/skill/ad-persistence
absec://builtin/dict/Auth%2Fpassword%2FTop100.txt
absec://builtin/payload/XSS%2Fevents.txt
absec://builtin/vuln/CVE-2021-44228
absec://nuclei/vuln/CVE-2021-44228
```

The ID is not based on SQLite `resources.id` because row IDs may change after rebuilds.

## Architecture

### Search layer

Add stable ID helpers in `internal/search`:

- `StableID(r Resource) string`
- `ParseStableID(id string) (source, typ, key string, err error)`
- `GetByStableID(db *sql.DB, id string) (*Resource, error)`

`GetByStableID` resolves by `source`, `type`, and `name`. This matches the existing schema's stable logical identity and avoids any migration.

### MCP search result shape

Update `ResourceSummary` in `internal/mcp/unified.go` with:

```go
ID string `json:"id"`
```

`resourceToSummary` computes the ID from the full `search.Resource` returned by `Search` or `ListByType`.

### Detail lookup

Extend `GetInput`:

```go
ID string `json:"id,omitempty"`
```

Resolution rules:

1. If `id` is present, parse and resolve it.
2. The resolved type must be `skill` or `vuln`.
3. If legacy `type` or `name` is also present and conflicts with the resolved resource, return a clear error.
4. If `id` is absent, preserve the existing `type/name` behavior.

`GetResult` should also include `id` so callers can keep referencing the exact resource.

### File lookup

Extend `GetFileInput`:

```go
ID string `json:"id,omitempty"`
```

Resolution rules:

1. If `id` is present, parse and resolve it.
2. The resolved type must be `dict` or `payload`.
3. If legacy `type` or `path` is also present and conflicts with the resolved resource, return a clear error.
4. Read from the resolved `Resource.FilePath` when using `id`.
5. If `id` is absent, preserve the existing `type/path` behavior.

`GetFileResult` should include `id` when available.

### Full-mode tools

Full-mode get adapters should accept `id` where relevant and pass it through to the unified handlers. Existing full-mode inputs stay compatible.

## Error Handling

Invalid ID errors should be explicit and actionable:

- missing `absec://` scheme
- wrong segment count
- empty source/type/key
- unsupported resource type
- malformed escaping
- valid ID that does not exist
- ID/legacy parameter mismatch

Mismatch errors should reject the call instead of silently preferring either side. This makes Agent mistakes visible during testing and prevents hidden wrong-resource reads.

## Testing Strategy

### Correctness tests

Add tests covering:

- search/list results include non-empty stable IDs
- repeated calls return the same ID for the same resource
- skill and vuln search results round-trip into `get_security_detail(id=...)`
- dict and payload search results round-trip into `read_security_file(id=...)`
- two resources with the same `type/name` but different `source` produce different IDs
- each source-qualified ID resolves to the correct source
- invalid IDs return clear errors
- `id` plus conflicting legacy parameters returns an error
- existing legacy `name/type/path` tests still pass

### Agent-style value tests

Add focused tests that model the ambiguity stable IDs are meant to remove:

1. Insert two vulnerability resources with the same name and type but different sources, such as `builtin` and `nuclei`.
2. Show that legacy `Get(type="vuln", name="CVE-2021-44228")` cannot select a specific source.
3. Show that `Get(id="absec://nuclei/vuln/CVE-2021-44228")` selects the intended source.
4. Repeat the same idea for dict/payload if useful.

These tests prove the value is correctness and disambiguation, not raw speed.

### Repeated validation commands

After implementation:

```bash
go test ./...
for i in $(seq 1 25); do go test ./... || exit 1; done
go test -run 'StableID|RoundTrip|InvalidID|SourceCollision|Ambiguity' ./internal/search ./internal/mcp -count=100
```

## Rollout

This is backward compatible for existing clients because old parameters remain supported. New clients should prefer IDs from search results.

Tool descriptions should say:

- search results include stable `id`
- detail/file tools prefer `id`
- legacy parameters remain supported

## Future Extensions

Stable IDs create a base for later features:

- source version pinning, such as `absec://aboutsecurity@666dc90/skill/sql-injection`
- chunk-level retrieval keyed by resource ID
- `topic/tokens` retrieval
- cache keys for detail and context-pack responses
- REST routes and UI links using the same resource IDs
