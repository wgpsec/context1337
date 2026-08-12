package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wgpsec/context1337/internal/search"
	"github.com/wgpsec/context1337/internal/storage"
	"github.com/wgpsec/context1337/internal/usage"
)

func setupUnifiedTest(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := storage.OpenDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		FilePath: "skills/sql-injection/SKILL.md", Category: "exploit",
		Tags:        "sqli,owasp,web",
		Description: "SQL Injection attack techniques",
		Body:        "SQL injection is a common web vulnerability",
	})
	search.InsertResource(db, search.Resource{
		Type: "skill", Name: "xss-reflected", Source: "builtin",
		FilePath: "skills/xss-reflected/SKILL.md", Category: "exploit",
		Tags:        "xss,owasp",
		Description: "Reflected XSS attacks",
		Body:        "Reflected cross-site scripting techniques",
	})
	search.InsertResource(db, search.Resource{
		Type: "dict", Name: "Auth/password/Top100.txt", Source: "builtin",
		Category: "auth", Description: "Common passwords top 100",
	})
	search.InsertResource(db, search.Resource{
		Type: "payload", Name: "XSS/events.txt", Source: "builtin",
		Category: "xss", Description: "XSS event handler payloads",
	})
	// Insert a vuln resource (raw row + FTS index)
	vres, _ := db.Exec(`INSERT INTO resources (type,name,source,file_path,category,tags,description,body,metadata)
		VALUES ('vuln','CVE-2021-44228','builtin','test/vuln.md','middleware','rce,jndi',
		'JNDI injection leads to RCE','## PoC\ntest payload',
		'{"severity":"CRITICAL","product":"Apache Log4j","vendor":"Apache","version_affected":"<2.17.0","fingerprint":"header=X-Log4j"}')`)
	vid, _ := vres.LastInsertId()
	search.IndexFTS(db, vid, "CVE-2021-44228", "JNDI injection leads to RCE", "rce,jndi", "middleware", "## PoC\ntest payload")

	return &Service{DB: db, DataDir: dir}
}

func TestSearch_Keyword(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "SQL injection", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
	if result.Items[0].Name != "sql-injection" {
		t.Errorf("top = %q, want sql-injection", result.Items[0].Name)
	}
	if result.Items[0].Type != "skill" {
		t.Errorf("type = %q, want skill", result.Items[0].Type)
	}
}

func TestSearch_ResponseAdvertisesSecurityConceptSearchVersion(t *testing.T) {
	svc := setupUnifiedTest(t)
	result, err := svc.Search(context.Background(), SearchInput{
		Query: "SQL injection",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"search_version":"security-concepts-v2"`) {
		t.Fatalf("search response does not advertise the active contract: %s", payload)
	}
}

func TestSearch_RelevanceCutoffDoesNotDropStrongResultAfterCanonicalRerank(t *testing.T) {
	svc := setupUnifiedTest(t)

	for i := 0; i < 40; i++ {
		if err := search.InsertResource(svc.DB, search.Resource{
			Type: "skill", Name: fmt.Sprintf("token-reference-%02d", i), Source: "builtin",
			FilePath:    fmt.Sprintf("skills/token-reference-%02d/SKILL.md", i),
			Category:    "general",
			Tags:        "jwt,token",
			Description: "JWT token format reference.",
			Body:        "Header payload signature.",
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, resource := range []search.Resource{
		{
			Type: "skill", Name: "jwt-attack-methodology", Source: "builtin",
			FilePath: "skills/jwt-attack-methodology/SKILL.md", Category: "exploit",
			Tags:        "jwt,authentication,bypass",
			Description: "JWT authentication bypass methodology.",
			Body:        "JWT authentication bypass.",
		},
		{
			Type: "skill", Name: "jwt-reference", Source: "builtin",
			FilePath: "skills/jwt-reference/SKILL.md", Category: "general",
			Tags:        "jwt",
			Description: "JWT reference.",
			Body:        strings.Repeat("unrelated protocol reference ", 1000) + " authentication bypass",
		},
		{
			Type: "skill", Name: "cookie-analysis", Source: "builtin",
			FilePath: "skills/cookie-analysis/SKILL.md", Category: "exploit",
			Tags:        "jwt,authentication,bypass",
			Description: "JWT authentication bypass through cookie analysis.",
			Body:        "JWT authentication bypass.",
		},
	} {
		if err := search.InsertResource(svc.DB, resource); err != nil {
			t.Fatal(err)
		}
	}

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "JWT authentication bypass",
		Type:  "skill",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	names := make(map[string]bool)
	for _, item := range result.Items {
		names[item.Name] = true
	}
	for _, expected := range []string{"jwt-attack-methodology", "jwt-reference", "cookie-analysis"} {
		if !names[expected] {
			t.Fatalf("%s was dropped after reranking; results=%v", expected, names)
		}
	}
}

func TestSearch_TypeFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "SQL", Type: "skill", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Items {
		if item.Type != "skill" {
			t.Errorf("item %q has type %q, want skill", item.Name, item.Type)
		}
	}
}

func TestSearch_EmptyQuery_ListAll(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total < 4 {
		t.Errorf("total = %d, want >= 4 (all non-vuln resource types)", result.Total)
	}
}

func TestSearch_EmptyQuery_TypeFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Type: "skill", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 2 {
		t.Errorf("total = %d, want 2", result.Total)
	}
	for _, item := range result.Items {
		if item.Type != "skill" {
			t.Errorf("item %q has type %q, want skill", item.Name, item.Type)
		}
	}
}

func TestSearch_ReturnsStructuredQueryComplexityOutcome(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "alpha bravo charlie delta echo foxtrot golf hotel india",
		Type:  "skill",
	})
	if err != nil {
		t.Fatalf("Search returned execution error: %v", err)
	}
	if result.Status != "query_too_complex" {
		t.Fatalf("status = %q, want query_too_complex", result.Status)
	}
	if result.Total != 0 || len(result.Items) != 0 {
		t.Fatalf("complexity result returned resources: %#v", result)
	}
	if !strings.Contains(result.Hint, "9") || !strings.Contains(result.Hint, "8") {
		t.Fatalf("hint = %q, want actual and maximum semantic group counts", result.Hint)
	}
}

func TestSearch_ComplexityRetriesPreserveProductIdentity(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "learun 力软 alpha bravo charlie delta echo foxtrot golf hotel india",
		Type:  "skill",
	})
	if err != nil {
		t.Fatalf("Search returned execution error: %v", err)
	}
	if result.Status != "query_too_complex" || len(result.RetryQueries) == 0 {
		t.Fatalf("complexity result = %#v, want focused retries", result)
	}
	for _, retry := range result.RetryQueries {
		if !strings.Contains(strings.ToLower(retry.Query), "learun") {
			t.Fatalf("retry dropped Learun product identity: %#v", retry)
		}
		if retry.Type != "skill" {
			t.Fatalf("retry type = %q, want skill", retry.Type)
		}
		if _, err := search.PlanQuery(retry.Query); err != nil {
			t.Fatalf("retry query %q is not executable: %v", retry.Query, err)
		}
	}
}

func TestSearch_MultiTopicNoMatchReturnsFocusedRetries(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "php sql注入 提权",
		Type:  "skill",
	})
	if err != nil {
		t.Fatalf("Search returned execution error: %v", err)
	}
	if result.Status != "no_match" {
		t.Fatalf("status = %q, want no_match", result.Status)
	}
	if len(result.RetryQueries) != 2 {
		t.Fatalf("retry queries = %#v, want one retry per security topic", result.RetryQueries)
	}
	queries := []string{result.RetryQueries[0].Query, result.RetryQueries[1].Query}
	if queries[0] != "php sql注入" || queries[1] != "php 提权" {
		t.Fatalf("retry queries = %v, want deterministic identity + topic retries", queries)
	}
	for _, retry := range result.RetryQueries {
		if retry.Type != "skill" {
			t.Fatalf("retry type = %q, want skill", retry.Type)
		}
		if _, err := search.PlanQuery(retry.Query); err != nil {
			t.Fatalf("retry query %q is not executable: %v", retry.Query, err)
		}
	}
}

func TestSearch_MultiTopicMatchDoesNotReturnFocusedRetries(t *testing.T) {
	svc := setupUnifiedTest(t)
	if err := search.InsertResource(svc.DB, search.Resource{
		Type:        "skill",
		Name:        "php-database-escalation-chain",
		Source:      "builtin",
		Tags:        "php,sql注入,提权",
		Description: "PHP SQL 注入后执行权限提升的组合攻击链。",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "php sql注入 提权",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "matched" || len(result.Items) == 0 {
		t.Fatalf("result = %#v, want matching combined skill", result)
	}
	if len(result.RetryQueries) != 0 {
		t.Fatalf("matched combined skill returned retries: %#v", result.RetryQueries)
	}
}

func TestSearch_PHPAttackChainNoMatchReturnsOneRetryPerTopic(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "php 反序列化 文件包含 日志投毒",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"php 反序列化", "php 文件包含", "php 日志投毒"}
	got := make([]string, len(result.RetryQueries))
	for index, retry := range result.RetryQueries {
		got[index] = retry.Query
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("retry queries = %v, want %v", got, want)
	}
}

func TestSearch_YiiAttackChainNoMatchReturnsOneRetryPerTopic(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "yii 反序列化 csrf 伪造",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"yii 反序列化", "yii csrf", "yii 伪造"}
	got := make([]string, len(result.RetryQueries))
	for index, retry := range result.RetryQueries {
		got[index] = retry.Query
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("retry queries = %v, want %v", got, want)
	}
}

func TestSearch_MultiTopicNoMatchWithoutIdentityStillReturnsSafeRetries(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "sql注入 提权",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sql注入", "提权"}
	got := make([]string, len(result.RetryQueries))
	for index, retry := range result.RetryQueries {
		got[index] = retry.Query
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("retry queries = %v, want %v", got, want)
	}
}

func TestSearch_MultiTopicNoMatchDoesNotReturnRetriesThatWouldDropIdentity(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "php java linux jwt sql注入 提权",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RetryQueries) != 0 {
		t.Fatalf("unsafe retries = %#v, want no suggestion when identities fill all focused-query slots", result.RetryQueries)
	}
}

func TestSearch_ComplexityOutcomeHasDedicatedUsageAccounting(t *testing.T) {
	svc := setupUnifiedTest(t)
	collector := usage.NewCollector()
	svc.Usage = collector

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "alpha bravo charlie delta echo foxtrot golf hotel india",
		Type:  "skill",
	})
	if err != nil || result.Status != "query_too_complex" {
		t.Fatalf("complexity search result=%#v err=%v", result, err)
	}

	metrics := collector.Snapshot().Search
	if metrics.RejectedComplexityTotal != 1 {
		t.Fatalf("rejected_complexity_total = %d, want 1", metrics.RejectedComplexityTotal)
	}
	if metrics.ZeroResultTotal != 0 || metrics.ErrorTotal != 0 || metrics.MatchedTotal != 0 {
		t.Fatalf("complexity outcome polluted another usage bucket: %#v", metrics)
	}
	if len(metrics.Queries) != 1 || metrics.Queries[0].RejectedComplexity != 1 {
		t.Fatalf("query metrics = %#v, want one complexity rejection", metrics.Queries)
	}
}

func TestSearch_CategoryFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Type: "skill", Category: "exploit", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Items {
		if item.Category != "exploit" {
			t.Errorf("item %q has category %q, want exploit", item.Name, item.Category)
		}
	}
}

func TestGet_Skill_Summary(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Get(ctx, GetInput{Name: "sql-injection", Type: "skill"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "sql-injection" {
		t.Errorf("name = %q", result.Name)
	}
	if result.Type != "skill" {
		t.Errorf("type = %q", result.Type)
	}
	if result.Body == "" {
		t.Error("summary depth should include body")
	}
}

func TestGet_Skill_Metadata(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Get(ctx, GetInput{Name: "sql-injection", Type: "skill", Depth: "metadata"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Body != "" {
		t.Error("metadata depth should not include body")
	}
}

func TestGet_Skill_Full_WithReferences(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()

	skillDir := filepath.Join(svc.DataDir, "skills", "exploit", "sql-injection")
	os.MkdirAll(filepath.Join(skillDir, "references"), 0o755)
	os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: sql-injection\n---\nbody"), 0o644)
	os.WriteFile(filepath.Join(skillDir, "references", "advanced.md"), []byte("# Advanced\nSQL techniques"), 0o644)

	svc.DB.Exec("UPDATE resources SET file_path=? WHERE name='sql-injection'",
		filepath.Join(skillDir, "SKILL.md"))

	result, err := svc.Get(ctx, GetInput{Name: "sql-injection", Type: "skill", Depth: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.References) != 1 {
		t.Fatalf("references = %d, want 1", len(result.References))
	}
}

func TestGet_NotFound(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	_, err := svc.Get(ctx, GetInput{Name: "nonexistent", Type: "skill"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGet_NotFound_ActionableError(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	_, err := svc.Get(ctx, GetInput{Name: "nonexistent", Type: "skill"})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "try search_security") {
		t.Errorf("error should contain recovery hint, got: %s", msg)
	}
	if !strings.Contains(msg, "not found") {
		t.Errorf("error should contain 'not found', got: %s", msg)
	}
}

func TestSearch_ZeroResults_HintWithType(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "nonexistent-xyz-999", Type: "skill", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 0 {
		t.Fatalf("expected 0 results, got %d", result.Total)
	}
	if result.Hint == "" {
		t.Fatal("expected hint when 0 results with type filter")
	}
	if !strings.Contains(result.Hint, "without the type filter") {
		t.Errorf("hint should suggest removing type filter, got: %s", result.Hint)
	}
}

func TestSearch_ZeroResults_HintWithoutType(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "nonexistent-xyz-999", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Hint == "" {
		t.Fatal("expected hint when 0 results")
	}
	if !strings.Contains(result.Hint, "broader") {
		t.Errorf("hint should suggest broader keywords, got: %s", result.Hint)
	}
}

func TestSearch_DefaultVulnExclusionReturnsActionableTypeHint(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{Query: "JNDI", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "no_match" || result.Total != 0 {
		t.Fatalf("default search unexpectedly returned vuln content: %#v", result)
	}
	if !strings.Contains(result.Hint, `type="vuln"`) {
		t.Fatalf("hint = %q, want an explicit type=vuln retry", result.Hint)
	}
}

func TestSearch_WithResults_NoHint(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "SQL injection", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Hint != "" {
		t.Errorf("should have no hint when results exist, got: %s", result.Hint)
	}
}

func TestGet_InvalidType(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	_, err := svc.Get(ctx, GetInput{Name: "test", Type: "dict"})
	if err == nil {
		t.Fatal("expected error for dict type")
	}
}

func TestGet_InvalidType_Tool(t *testing.T) {
	svc := setupUnifiedTest(t)
	ctx := context.Background()
	_, err := svc.Get(ctx, GetInput{Name: "test", Type: "tool"})
	if err == nil {
		t.Fatal("expected error for tool type")
	}
}

func TestSearch_VulnExcludedByDefault(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Search(context.Background(), SearchInput{Query: "injection", Limit: 20})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, item := range res.Items {
		if item.Type == "vuln" {
			t.Errorf("vuln should not appear in default search, got %q", item.Name)
		}
	}
}

func TestSearch_VulnWithExplicitType(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Search(context.Background(), SearchInput{Query: "JNDI injection", Type: "vuln", Limit: 20})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total == 0 {
		t.Fatal("expected vuln results with type=vuln")
	}
	if res.Items[0].Severity != "CRITICAL" {
		t.Errorf("Severity = %q, want CRITICAL", res.Items[0].Severity)
	}
	if res.Items[0].Product != "Apache Log4j" {
		t.Errorf("Product = %q", res.Items[0].Product)
	}
}

func TestSearch_VulnSeverityFilter(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Search(context.Background(), SearchInput{
		Type: "vuln", Severity: "CRITICAL", Limit: 20,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Total != 1 {
		t.Errorf("total = %d, want 1", res.Total)
	}
}

func TestGet_Vuln_Brief(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Get(context.Background(), GetInput{Name: "CVE-2021-44228", Type: "vuln"})
	if err != nil {
		t.Fatalf("Get vuln: %v", err)
	}
	if res.Severity != "CRITICAL" {
		t.Errorf("Severity = %q", res.Severity)
	}
	if res.Product != "Apache Log4j" {
		t.Errorf("Product = %q", res.Product)
	}
	if res.Body != "" {
		t.Error("brief mode should not include body")
	}
}

func TestSearch_SkillSizeMetadata(t *testing.T) {
	svc := setupUnifiedTest(t)
	svc.DB.Exec(`UPDATE resources SET metadata='{"body_lines":150,"ref_count":2}' WHERE name='sql-injection'`)

	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "SQL injection", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
	found := false
	for _, item := range result.Items {
		if item.Name == "sql-injection" {
			found = true
			if item.BodyLines != 150 {
				t.Errorf("BodyLines = %d, want 150", item.BodyLines)
			}
			if item.RefCount != 2 {
				t.Errorf("RefCount = %d, want 2", item.RefCount)
			}
		}
	}
	if !found {
		t.Error("sql-injection not in results")
	}
}

func TestSearch_DictSizeMetadata(t *testing.T) {
	svc := setupUnifiedTest(t)
	svc.DB.Exec(`UPDATE resources SET metadata='{"lines":586}' WHERE name='Auth/password/Top100.txt'`)

	ctx := context.Background()
	result, err := svc.Search(ctx, SearchInput{Query: "password", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range result.Items {
		if item.Name == "Auth/password/Top100.txt" {
			found = true
			if item.Lines != 586 {
				t.Errorf("Lines = %d, want 586", item.Lines)
			}
		}
	}
	if !found {
		t.Error("dict not in results")
	}
}

func TestGet_Vuln_Full(t *testing.T) {
	svc := setupUnifiedTest(t)
	res, err := svc.Get(context.Background(), GetInput{Name: "CVE-2021-44228", Type: "vuln", Depth: "full"})
	if err != nil {
		t.Fatalf("Get vuln full: %v", err)
	}
	if res.Body == "" {
		t.Error("full mode should include body")
	}
	if res.Fingerprint != "header=X-Log4j" {
		t.Errorf("Fingerprint = %q", res.Fingerprint)
	}
}

func TestSearch_ReturnsStableIDs(t *testing.T) {
	svc := setupUnifiedTest(t)
	result, err := svc.Search(context.Background(), SearchInput{Query: "SQL injection", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) == 0 {
		t.Fatal("expected results")
	}
	for _, item := range result.Items {
		if item.ID == "" {
			t.Fatalf("item %#v has empty ID", item)
		}
		if !strings.HasPrefix(item.ID, "absec://") {
			t.Fatalf("ID = %q, want absec:// prefix", item.ID)
		}
	}
}

func TestGet_WithStableID_SkillRoundTrip(t *testing.T) {
	svc := setupUnifiedTest(t)
	searchResult, err := svc.Search(context.Background(), SearchInput{Query: "SQL injection", Type: "skill", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(searchResult.Items) == 0 {
		t.Fatal("expected skill search result")
	}
	got, err := svc.Get(context.Background(), GetInput{ID: searchResult.Items[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != searchResult.Items[0].ID {
		t.Fatalf("ID = %q, want %q", got.ID, searchResult.Items[0].ID)
	}
	if got.Name != "sql-injection" || got.Type != "skill" || got.Source != "builtin" {
		t.Fatalf("got (%q, %q, %q), want (sql-injection, skill, builtin)", got.Name, got.Type, got.Source)
	}
}

func TestGet_WithStableID_VulnRoundTrip(t *testing.T) {
	svc := setupUnifiedTest(t)
	searchResult, err := svc.Search(context.Background(), SearchInput{Query: "JNDI", Type: "vuln", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(searchResult.Items) == 0 {
		t.Fatal("expected vuln search result")
	}
	got, err := svc.Get(context.Background(), GetInput{ID: searchResult.Items[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != searchResult.Items[0].ID {
		t.Fatalf("ID = %q, want %q", got.ID, searchResult.Items[0].ID)
	}
	if got.Name != "CVE-2021-44228" || got.Type != "vuln" || got.Source != "builtin" {
		t.Fatalf("got (%q, %q, %q), want (CVE-2021-44228, vuln, builtin)", got.Name, got.Type, got.Source)
	}
}

func TestGet_WithStableID_RejectsLegacyMismatch(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.Get(context.Background(), GetInput{ID: "absec://builtin/skill/sql-injection", Type: "skill", Name: "xss-reflected"})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("error = %q, want conflict", err.Error())
	}
}

func TestGet_WithStableID_SourceCollision_AgentAmbiguity(t *testing.T) {
	svc := setupUnifiedTest(t)
	_, err := svc.DB.Exec(`INSERT INTO resources (type,name,source,file_path,category,tags,description,body,metadata)
		VALUES ('vuln','CVE-2021-44228','nuclei','nuclei/http/cves/CVE-2021-44228.yaml','middleware','rce,jndi',
		'Nuclei Log4j template','nuclei yaml body',
		'{"severity":"CRITICAL","product":"Apache Log4j","vendor":"ProjectDiscovery"}')`)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := svc.Get(context.Background(), GetInput{Name: "CVE-2021-44228", Type: "vuln"})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Source == "" {
		t.Fatal("legacy lookup should return a source")
	}
	stable, err := svc.Get(context.Background(), GetInput{ID: "absec://nuclei/vuln/CVE-2021-44228"})
	if err != nil {
		t.Fatal(err)
	}
	if stable.Source != "nuclei" {
		t.Fatalf("stable Source = %q, want nuclei", stable.Source)
	}
	if stable.Vendor != "ProjectDiscovery" {
		t.Fatalf("stable Vendor = %q, want ProjectDiscovery", stable.Vendor)
	}
}

func TestTrimByRelevance(t *testing.T) {
	mk := func(score float64) search.SearchResult {
		return search.SearchResult{Score: score}
	}

	tests := []struct {
		name  string
		input []search.SearchResult
		wantN int
	}{
		{"empty", nil, 0},
		{"single", []search.SearchResult{mk(-10)}, 1},
		{"all relevant", []search.SearchResult{mk(-10), mk(-8), mk(-5)}, 3},
		{
			"trim tail",
			[]search.SearchResult{mk(-20), mk(-10), mk(-5), mk(-1), mk(-0.5)},
			3, // -1 is 5% of -20, below 20% cutoff
		},
		{
			"reranked order still keeps later strong result",
			[]search.SearchResult{mk(-10), mk(-1), mk(-9)},
			2,
		},
		{
			"only best survives",
			[]search.SearchResult{mk(-50), mk(-2), mk(-1)},
			1, // -2 is 4% of -50
		},
		{"non-negative guard", []search.SearchResult{mk(0), mk(-1)}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimByRelevance(tt.input)
			if len(got) != tt.wantN {
				scores := make([]float64, len(got))
				for i, r := range got {
					scores[i] = r.Score
				}
				t.Errorf("trimByRelevance() kept %d items (want %d), scores=%v", len(got), tt.wantN, scores)
			}
		})
	}
}

func TestSearch_RelevanceCutoff_AdjustsTotal(t *testing.T) {
	svc := setupUnifiedTest(t)
	// "SQL" matches sql-injection strongly (name+description+body) but
	// xss-payloads only weakly (body mentions "SQL" once).
	// The cutoff should trim weak matches and adjust total accordingly.
	res, err := svc.Search(context.Background(), SearchInput{Query: "sql", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	// Total should equal len(Items) when cutoff trims within a single page
	if res.Total != len(res.Items) {
		t.Errorf("Total=%d but len(Items)=%d; cutoff should align total with trimmed results", res.Total, len(res.Items))
	}
}

func TestDiversifyByType(t *testing.T) {
	mk := func(typ string, score float64) search.SearchResult {
		return search.SearchResult{
			Resource: search.Resource{Type: typ},
			Score:    score,
		}
	}

	tests := []struct {
		name      string
		input     []search.SearchResult
		wantOrder []string // expected type sequence
	}{
		{"empty", nil, nil},
		{"single type", []search.SearchResult{mk("skill", -10), mk("skill", -8)}, []string{"skill", "skill"}},
		{
			"two types interleaved",
			[]search.SearchResult{
				mk("payload", -10), mk("payload", -9), mk("payload", -8),
				mk("skill", -7), mk("skill", -6),
			},
			[]string{"payload", "skill", "payload", "skill", "payload"},
		},
		{
			"three types",
			[]search.SearchResult{
				mk("payload", -10), mk("payload", -9),
				mk("skill", -8),
				mk("dict", -7),
			},
			[]string{"payload", "skill", "dict", "payload"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diversifyByType(tt.input)
			if len(got) != len(tt.input) {
				t.Fatalf("diversify changed count: %d -> %d", len(tt.input), len(got))
			}
			gotTypes := make([]string, len(got))
			for i, r := range got {
				gotTypes[i] = r.Type
			}
			if tt.wantOrder != nil {
				for i, want := range tt.wantOrder {
					if i >= len(gotTypes) || gotTypes[i] != want {
						t.Errorf("position %d: got %v, want %v\nfull: %v", i, gotTypes, tt.wantOrder, gotTypes)
						break
					}
				}
			}
		})
	}
}
