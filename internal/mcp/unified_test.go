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

func TestSearch_TransliteratesUnknownChineseContextAfterExactNoMatch(t *testing.T) {
	svc := setupUnifiedTest(t)
	if err := search.InsertResource(svc.DB, search.Resource{
		Type:        "vuln",
		Name:        "CNVD-2021-32799",
		Source:      "nuclei",
		FilePath:    "http/cnvd/2021/CNVD-2021-32799.yaml",
		Category:    "nuclei-cnvd",
		Tags:        "cnvd2021,cnvd,360,xintianqing,sqli,vuln",
		Description: "Tianqing Terminal Security Management System SQL injection",
		Metadata:    `{"severity":"HIGH"}`,
	}); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "天擎 360 sqli",
		Type:  "vuln",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "matched" || len(result.Items) != 1 {
		t.Fatalf("result = %#v, want one transliterated match", result)
	}
	if result.Items[0].ID != "absec://nuclei/vuln/CNVD-2021-32799" {
		t.Fatalf("stable ID = %q", result.Items[0].ID)
	}
	if result.Resolution == nil || result.Resolution.Mode != "transliterated" {
		t.Fatalf("resolution = %#v, want transliterated", result.Resolution)
	}
	if result.Resolution.OriginalQuery != "天擎 360 sqli" || result.Resolution.EffectiveQuery != "tianqing 360 sqli" {
		t.Fatalf("resolution query mapping = %#v", result.Resolution)
	}
	if len(result.Resolution.Transliterations) != 1 ||
		result.Resolution.Transliterations[0].From != "天擎" ||
		result.Resolution.Transliterations[0].To != "tianqing" {
		t.Fatalf("transliterations = %#v", result.Resolution.Transliterations)
	}
	if fmt.Sprint(result.AttemptedStrategies) != "[exact pinyin]" {
		t.Fatalf("attempted strategies = %v", result.AttemptedStrategies)
	}
}

func TestSearch_PinyinNoMatchReturnsLLMGuidanceWithoutDroppingKeywords(t *testing.T) {
	svc := setupUnifiedTest(t)
	if err := search.InsertResource(svc.DB, search.Resource{
		Type:        "vuln",
		Name:        "CNVD-2021-32799",
		Source:      "nuclei",
		Tags:        "360,xintianqing,sqli,vuln",
		Description: "Tianqing Terminal Security Management System SQL injection",
		Metadata:    `{"severity":"HIGH"}`,
	}); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "getsimilarlist 360 天擎 sqli",
		Type:  "vuln",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "no_match" || result.Total != 0 || len(result.Items) != 0 {
		t.Fatalf("result = %#v, want no_match without broadened results", result)
	}
	if fmt.Sprint(result.AttemptedStrategies) != "[exact pinyin]" {
		t.Fatalf("attempted strategies = %v", result.AttemptedStrategies)
	}
	wantActions := []string{"translate_to_english", "reduce_keywords"}
	gotActions := make([]string, len(result.RetryGuidance))
	for index, guidance := range result.RetryGuidance {
		gotActions[index] = guidance.Action
	}
	if fmt.Sprint(gotActions) != fmt.Sprint(wantActions) {
		t.Fatalf("guidance actions = %v, want %v", gotActions, wantActions)
	}
	if !strings.Contains(result.Hint, "Exact and pinyin searches returned no results") {
		t.Fatalf("hint = %q, want attempted-strategy guidance", result.Hint)
	}
	if result.Resolution != nil {
		t.Fatalf("unresolved query returned a matched resolution: %#v", result.Resolution)
	}
}

func TestSearch_ExactChineseMatchDoesNotAdvertiseFallback(t *testing.T) {
	svc := setupUnifiedTest(t)
	if err := search.InsertResource(svc.DB, search.Resource{
		Type: "vuln", Name: "exact-chinese-product", Source: "nuclei",
		Tags: "天擎,sqli", Description: "天擎 SQL 注入", Metadata: `{"severity":"HIGH"}`,
	}); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Search(context.Background(), SearchInput{Query: "天擎 sqli", Type: "vuln"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "matched" || len(result.Items) != 1 {
		t.Fatalf("result = %#v, want exact match", result)
	}
	if result.Resolution != nil || len(result.AttemptedStrategies) != 0 || len(result.RetryGuidance) != 0 {
		t.Fatalf("exact match exposed fallback metadata: %#v", result)
	}
}

func TestSearch_PinyinFallbackDoesNotBypassDefaultVulnerabilityExclusion(t *testing.T) {
	svc := setupUnifiedTest(t)
	if err := search.InsertResource(svc.DB, search.Resource{
		Type: "vuln", Name: "CNVD-2021-32799", Source: "nuclei",
		Tags: "360,tianqing,sqli", Description: "Tianqing SQL injection",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Search(context.Background(), SearchInput{Query: "天擎 360 sqli"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "no_match" || len(result.Items) != 0 {
		t.Fatalf("default search exposed vuln through fallback: %#v", result)
	}
	if !strings.Contains(result.Hint, `type="vuln"`) {
		t.Fatalf("hint = %q, want explicit vuln filter guidance", result.Hint)
	}
}

func TestSearch_PinyinFallbackIsDisabledForLaterPages(t *testing.T) {
	svc := setupUnifiedTest(t)
	if err := search.InsertResource(svc.DB, search.Resource{
		Type: "vuln", Name: "CNVD-2021-32799", Source: "nuclei",
		Tags: "360,tianqing,sqli", Description: "Tianqing SQL injection",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "天擎 360 sqli", Type: "vuln", Offset: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The exact search matched nothing, and fallback is off for later pages, so
	// the page over the exact result set is empty. Reporting the fallback's row
	// count here would hand the client a total that page 0 cannot reproduce.
	if result.Status != "no_match" || result.Total != 0 || len(result.Items) != 0 {
		t.Fatalf("later page reported results the exact search never returned: %#v", result)
	}
	if result.Resolution != nil || len(result.AttemptedStrategies) != 1 || result.AttemptedStrategies[0] != "exact" {
		t.Fatalf("later page attempted fallback: %#v", result)
	}

	// Suppressing fallback must not suppress it for first pages, which is the
	// only place it is allowed to run.
	first, err := svc.Search(context.Background(), SearchInput{Query: "天擎 360 sqli", Type: "vuln"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != "matched" || first.Total != 1 || len(first.Items) != 1 {
		t.Fatalf("first page lost pinyin fallback: %#v", first)
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
	if !strings.Contains(string(payload), `"search_version":"security-concepts-v3"`) {
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

// A prose query with unrecognised filler must still offer a narrower retry, and
// must say which words the narrowing left out. Before this, a single-topic query
// produced no retry at all (the builder required two topics), and the retries
// that were produced carried the filler forward and returned nothing.
func TestSearch_NoMatchRetryDropsFillerAndReportsIt(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "sql注入 怎么 利用",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "no_match" {
		t.Fatalf("status = %q, want no_match", result.Status)
	}
	if len(result.RetryQueries) != 1 {
		t.Fatalf("retry queries = %#v, want one focused retry", result.RetryQueries)
	}
	retry := result.RetryQueries[0]
	if retry.Query != "sql注入" {
		t.Fatalf("retry query = %q, want the recognised concept alone", retry.Query)
	}
	if fmt.Sprint(retry.DroppedTerms) != "[怎么 利用]" {
		t.Fatalf("dropped terms = %v, want the unrecognised words named", retry.DroppedTerms)
	}
	if retry.Type != "skill" {
		t.Fatalf("retry type = %q, want the caller's type preserved", retry.Type)
	}
	if !strings.Contains(result.Hint, "dropped: 怎么, 利用") {
		t.Fatalf("hint = %q, want the dropped terms to be visible without parsing retry_queries", result.Hint)
	}
	if _, err := search.PlanQuery(retry.Query); err != nil {
		t.Fatalf("retry query %q is not executable: %v", retry.Query, err)
	}
}

// The retry must actually return something. A suggestion that reproduces the
// empty result is worse than no suggestion: it costs the caller a round trip and
// reads as if the corpus had nothing to say.
func TestSearch_NoMatchRetryReturnsResultsWhenTheConceptExists(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "sql注入 怎么 利用",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.RetryQueries) != 1 {
		t.Fatalf("retry queries = %#v, want one", result.RetryQueries)
	}

	retry := result.RetryQueries[0]
	followed, err := svc.Search(context.Background(), SearchInput{Query: retry.Query, Type: retry.Type})
	if err != nil {
		t.Fatal(err)
	}
	if followed.Status != "matched" || len(followed.Items) == 0 {
		t.Fatalf("following the retry returned nothing: %#v", followed)
	}
}

// A named product in a prose question must still yield a usable retry. This is
// the shape an agent writes, and it is the reason the registry carries product
// identity concepts: without them nothing in the query is recognised, so the
// caller is told to reduce keywords with no indication of which one carries the
// question.
func TestSearch_NoMatchRetrySurvivesNamedProduct(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "tomcat 弱口令 怎么 打",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "no_match" {
		t.Fatalf("status = %q, want no_match for a query the corpus does not contain", result.Status)
	}
	if len(result.RetryQueries) == 0 {
		t.Fatal("no retry offered; a recognised product must be enough to suggest one")
	}
	// The retry keeps the recognised concepts and names what it left out.
	retry := result.RetryQueries[0]
	if !strings.Contains(retry.Query, "tomcat") {
		t.Fatalf("retry query = %q, want it to keep the recognised product", retry.Query)
	}
	if len(retry.DroppedTerms) == 0 {
		t.Fatal("dropped terms empty; the unrecognised words must be named")
	}
	if _, err := search.PlanQuery(retry.Query); err != nil {
		t.Fatalf("retry query %q is not executable: %v", retry.Query, err)
	}
}

// A query the planner recognised nothing in must not get a guessed retry. There
// is no concept to narrow toward, and inventing one would be the "伪造 retries"
// the closure design rules out.
func TestSearch_NoMatchWithoutRecognisedConceptsReturnsNoRetry(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "zzzznothing 怎么 yyyynothing",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "no_match" {
		t.Fatalf("status = %q, want no_match", result.Status)
	}
	if len(result.RetryQueries) != 0 {
		t.Fatalf("invented retries = %#v, want none", result.RetryQueries)
	}
}

// The complexity path is a different contract: it fires before any FTS query
// runs, and its retries keep the context groups because the query was never
// executed, so nothing is known about which words would fail.
func TestSearch_ComplexityRetriesKeepSpecShapedAllocation(t *testing.T) {
	svc := setupUnifiedTest(t)

	result, err := svc.Search(context.Background(), SearchInput{
		Query: "learun 力软 alpha bravo charlie delta echo foxtrot golf hotel india",
		Type:  "skill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "query_too_complex" {
		t.Fatalf("status = %q, want query_too_complex", result.Status)
	}
	for _, retry := range result.RetryQueries {
		if len(retry.DroppedTerms) != 0 {
			t.Fatalf("complexity retry reported dropped terms: %#v", retry)
		}
		if !strings.Contains(strings.ToLower(retry.Query), "learun") {
			t.Fatalf("complexity retry dropped product identity: %#v", retry)
		}
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

// A typed search used to fetch only one page of candidates and then run the
// relevance trim over it, so `total` grew with the offset: the caller paging
// through 26 real matches was told 5, then 10, then 15, and a client that stops
// when offset+limit reaches total would quit after the first page. The typed
// path now reads the same candidate window the cross-type path does, so total
// is a property of the result set rather than of the page being viewed.
func TestSearch_TypedPaginationTotalIsStableAcrossOffsets(t *testing.T) {
	svc := setupPaginationTest(t)
	const limit = 5

	first, err := svc.Search(context.Background(), SearchInput{
		Query: "pagingmarker", Type: "skill", Limit: limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Total <= limit {
		t.Fatalf("fixture too small: typed total = %d, want more than one page", first.Total)
	}

	for offset := 0; offset <= first.Total; offset += limit {
		res, err := svc.Search(context.Background(), SearchInput{
			Query: "pagingmarker", Type: "skill", Offset: offset, Limit: limit,
		})
		if err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
		if res.Total != first.Total {
			t.Fatalf("offset %d: typed total = %d, want the first page's %d",
				offset, res.Total, first.Total)
		}
	}
}

// setupPaginationTest builds a store with more matching rows than any single
// page, spread across several types so cross-type diversification is in play.
func setupPaginationTest(t *testing.T) *Service {
	t.Helper()
	svc := setupUnifiedTest(t)
	for i := 0; i < 12; i++ {
		for _, typ := range []string{"skill", "dict", "payload"} {
			if err := search.InsertResource(svc.DB, search.Resource{
				Type: typ, Name: fmt.Sprintf("%s-paging-%02d", typ, i), Source: "builtin",
				FilePath:    fmt.Sprintf("test/%s-%02d.md", typ, i),
				Category:    "paging",
				Tags:        "pagingmarker",
				Description: "pagingmarker probe row",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return svc
}

// A search must report the size of its result set, not the size of whatever
// prefix it read to compute the ranking. Ranking here is not order-preserving
// (the relevance trim needs the best score in the list, cross-type diversify
// needs every type's candidates), so the ranked list has to be the whole match
// set. When the candidate window was a real cap, `total` was an artifact of it:
// a query matching 400 rows reported 300 until the caller paged far enough to
// slide the window past the cap, and a client that stops when
// `offset+limit >= total` never saw the last 100.
func TestSearch_TotalIsNotCappedByCandidateWindow(t *testing.T) {
	svc := setupUnifiedTest(t)
	const rows = 320

	for i := 0; i < rows; i++ {
		if err := search.InsertResource(svc.DB, search.Resource{
			Type: "skill", Name: fmt.Sprintf("windowmarker-%03d", i), Source: "builtin",
			FilePath:    fmt.Sprintf("test/window-%03d.md", i),
			Category:    "window",
			Tags:        "windowmarker",
			Description: "windowmarker probe row",
		}); err != nil {
			t.Fatal(err)
		}
	}

	first, err := svc.Search(context.Background(), SearchInput{
		Query: "windowmarker", Type: "skill", Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != rows {
		t.Fatalf("total = %d, want all %d matching rows", first.Total, rows)
	}

	// Paging to the end must be able to reach the last row, which it cannot if
	// the window stops short of the match set.
	last := rows - rows%10 - 10
	res, err := svc.Search(context.Background(), SearchInput{
		Query: "windowmarker", Type: "skill", Offset: last, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Total != rows {
		t.Fatalf("offset %d: total = %d, want %d", last, res.Total, rows)
	}
	if len(res.Items) != 10 {
		t.Fatalf("offset %d: returned %d items, want 10", last, len(res.Items))
	}
}

// Cross-type search re-ranks the candidate list before slicing a page. When
// each page was fetched with the caller's SQL offset but sliced from a
// differently-ordered window, later pages repeated rows the client had already
// seen. Every page must now be a slice of one ranked list.
func TestSearch_CrossTypePaginationReturnsNoDuplicates(t *testing.T) {
	svc := setupPaginationTest(t)
	const limit = 5

	seen := make(map[string]struct{})
	var total int
	for offset := 0; ; offset += limit {
		res, err := svc.Search(context.Background(), SearchInput{
			Query: "pagingmarker", Offset: offset, Limit: limit,
		})
		if err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
		if offset == 0 {
			total = res.Total
			if total <= limit {
				t.Fatalf("fixture too small: total = %d, want more than one page", total)
			}
		}
		if res.Total != total {
			t.Fatalf("offset %d: total = %d, want stable %d", offset, res.Total, total)
		}
		if len(res.Items) == 0 {
			break
		}
		for _, item := range res.Items {
			if _, dup := seen[item.ID]; dup {
				t.Fatalf("offset %d: item id %q repeated across pages", offset, item.ID)
			}
			seen[item.ID] = struct{}{}
		}
	}
	if len(seen) != total {
		t.Fatalf("walked %d distinct items before running dry, want %d", len(seen), total)
	}
}

// total must describe the pageable result set, so it may not grow as the caller
// paginates. It used to collapse to offset+len(results) once a page happened to
// come back short, which made total track the last offset the client requested
// rather than the number of rows it can actually page through.
func TestSearch_PaginationTotalIsConsistentAcrossWindows(t *testing.T) {
	svc := setupPaginationTest(t)
	const limit = 5

	first, err := svc.Search(context.Background(), SearchInput{Query: "pagingmarker", Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	if first.Total <= limit {
		t.Fatalf("fixture too small: total = %d, want more than one page", first.Total)
	}

	for _, offset := range []int{limit, first.Total - 1, first.Total, 10_000} {
		res, err := svc.Search(context.Background(), SearchInput{
			Query: "pagingmarker", Offset: offset, Limit: limit,
		})
		if err != nil {
			t.Fatalf("offset %d: %v", offset, err)
		}
		if res.Total != first.Total {
			t.Fatalf("offset %d: total = %d, want %d", offset, res.Total, first.Total)
		}
	}

	typed, err := svc.Search(context.Background(), SearchInput{Query: "pagingmarker", Type: "skill", Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	if typed.Total > first.Total {
		t.Fatalf("typed total = %d exceeds untyped total = %d", typed.Total, first.Total)
	}

	last, err := svc.Search(context.Background(), SearchInput{
		Query: "pagingmarker", Offset: first.Total - 1, Limit: limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(last.Items) == 0 {
		t.Fatalf("offset %d returned no rows although total = %d", first.Total-1, first.Total)
	}
}

func TestSearch_OffsetBeyondTotalReturnsEmptyPage(t *testing.T) {
	svc := setupPaginationTest(t)

	res, err := svc.Search(context.Background(), SearchInput{
		Query: "pagingmarker", Offset: 10_000, Limit: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Items) != 0 {
		t.Fatalf("offset past the end returned %d items: %#v", len(res.Items), res.Items)
	}
	if res.Status != "matched" || res.Total == 0 {
		t.Fatalf("offset past the end changed the result set: %#v", res)
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
