package search

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/wgpsec/context1337/internal/storage"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.OpenDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestInsertResource(t *testing.T) {
	db := setupTestDB(t)
	err := InsertResource(db, Resource{
		Type:        "skill",
		Name:        "sql-injection",
		Source:      "builtin",
		FilePath:    "skills/sql-injection/SKILL.md",
		Category:    "exploit",
		Tags:        "sqli,owasp,web",
		Description: "SQL Injection attack techniques",
		Body:        "SQL injection is a common web security vulnerability",
	})
	if err != nil {
		t.Fatalf("InsertResource: %v", err)
	}
}

func TestSearch_ByKeyword(t *testing.T) {
	db := setupTestDB(t)

	InsertResource(db, Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		FilePath: "skills/sql-injection/SKILL.md", Category: "exploit",
		Tags: "sqli,owasp", Description: "SQL Injection techniques",
		Body: "SQL injection attack details",
	})
	InsertResource(db, Resource{
		Type: "skill", Name: "xss-reflected", Source: "builtin",
		FilePath: "skills/xss-reflected/SKILL.md", Category: "exploit",
		Tags: "xss,owasp", Description: "Reflected XSS attacks",
		Body: "Reflected cross-site scripting attack",
	})

	results, _, err := Search(db, SearchQuery{
		Query: "SQL Injection",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected results, got none")
	}
	if results[0].Name != "sql-injection" {
		t.Errorf("top result = %q, want sql-injection", results[0].Name)
	}
}

func TestSearch_ChinesePhraseOnlyInNameUsesTheQueryTokenizer(t *testing.T) {
	db := setupTestDB(t)
	if err := InsertResource(db, Resource{
		Type:     "skill",
		Name:     "深蓝平台",
		Source:   "builtin",
		Category: "reference",
	}); err != nil {
		t.Fatal(err)
	}

	results, _, err := Search(db, SearchQuery{
		Query: "深蓝平台",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultNames(results); len(got) != 1 || got[0] != "深蓝平台" {
		t.Fatalf("results = %v, want name-only Chinese resource", got)
	}
}

func TestSearch_ChinesePhraseOnlyInCategoryUsesTheQueryTokenizer(t *testing.T) {
	db := setupTestDB(t)
	if err := InsertResource(db, Resource{
		Type:     "skill",
		Name:     "category-only-resource",
		Source:   "builtin",
		Category: "身份鉴别",
	}); err != nil {
		t.Fatal(err)
	}

	results, _, err := Search(db, SearchQuery{
		Query: "身份鉴别",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultNames(results); len(got) != 1 || got[0] != "category-only-resource" {
		t.Fatalf("results = %v, want category-only Chinese resource", got)
	}
}

func TestReindexFTS_MakesRawChineseContentSearchableWithTheQueryTokenizer(t *testing.T) {
	db := setupTestDB(t)
	result, err := db.Exec(`
		INSERT INTO resources
			(type, name, source, file_path, category, tags, description, body, metadata)
		VALUES
			('vuln', 'CVE-2023-1454', 'builtin', 'Vuln/CVE-2023-1454.md',
			 'middleware', 'sqli', 'JeecgBoot 积木报表 SQL 注入漏洞', '', '{}')`)
	if err != nil {
		t.Fatal(err)
	}
	resourceID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`
		INSERT INTO resources_fts(rowid, name, description, tags, category, body)
		VALUES (?, 'CVE-2023-1454', 'JeecgBoot 积木 报表 SQL 注入 漏洞', 'sqli', 'middleware', '')`,
		resourceID); err != nil {
		t.Fatal(err)
	}

	before, _, err := Search(db, SearchQuery{Query: "积木报表", Type: "vuln", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 0 {
		t.Fatalf("precondition failed: legacy jieba-shaped index unexpectedly matched %v", resultNames(before))
	}

	if err := ReindexFTS(db); err != nil {
		t.Fatal(err)
	}

	after, _, err := Search(db, SearchQuery{Query: "积木报表", Type: "vuln", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got := resultNames(after); len(got) != 1 || got[0] != "CVE-2023-1454" {
		t.Fatalf("results after reindex = %v, want CVE-2023-1454", got)
	}
}

func TestSearch_ReturnsLightweightCandidatesWithoutLoadingBody(t *testing.T) {
	db := setupTestDB(t)
	if err := InsertResource(db, Resource{
		Type: "skill", Name: "body-only-match", Source: "builtin",
		Description: "lightweight summary",
		Body:        "bodymarker " + strings.Repeat("large content ", 1000),
	}); err != nil {
		t.Fatal(err)
	}

	results, _, err := Search(db, SearchQuery{Query: "bodymarker", Type: "skill", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %v, want body-indexed resource", resultNames(results))
	}
	if results[0].Body != "" {
		t.Fatalf("search candidate loaded %d body bytes; summaries must stay lightweight", len(results[0].Body))
	}
}

func TestSearch_JWTAlgorithmConfusionMatchesEquivalentChineseConcept(t *testing.T) {
	db := setupTestDB(t)

	if err := InsertResource(db, Resource{
		Type: "skill", Name: "jwt-attack-methodology", Source: "builtin",
		FilePath: "skills/jwt-attack-methodology/SKILL.md", Category: "exploit",
		Tags:        "jwt,HS256,RS256,算法混淆",
		Description: "JWT 攻击方法论，覆盖 RS256 到 HS256 算法混淆。",
		Body:        "验证 JWT 签名算法并安全构造测试 token。",
	}); err != nil {
		t.Fatal(err)
	}
	if err := InsertResource(db, Resource{
		Type: "skill", Name: "generic-auth-audit", Source: "builtin",
		FilePath: "skills/generic-auth-audit/SKILL.md", Category: "code-audit",
		Tags:        "jwt,algorithm,confusion",
		Description: "Generic JWT algorithm confusion audit notes.",
		Body:        "Broad authentication review.",
	}); err != nil {
		t.Fatal(err)
	}

	results, _, err := Search(db, SearchQuery{
		Query: "JWT algorithm confusion",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, result := range results {
		if result.Name == "jwt-attack-methodology" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("jwt-attack-methodology missing from results: %v", resultNames(results))
	}
}

func TestSearch_JWTNoneAlgorithmBypassRequiresEverySemanticGroup(t *testing.T) {
	db := setupTestDB(t)

	for _, resource := range []Resource{
		{
			Type: "skill", Name: "jwt-attack-methodology", Source: "builtin",
			FilePath: "skills/jwt-attack-methodology/SKILL.md", Category: "exploit",
			Tags:        "jwt,alg none",
			Description: "JWT alg:none 空算法绕过方法论。",
			Body:        "构造无签名 token 验证认证绕过。",
		},
		{
			Type: "skill", Name: "jwt-format-reference", Source: "builtin",
			FilePath: "skills/jwt-format-reference/SKILL.md", Category: "general",
			Tags:        "jwt,none,algorithm",
			Description: "JWT none algorithm token format reference.",
			Body:        "Describes token structure only.",
		},
	} {
		if err := InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}

	results, _, err := Search(db, SearchQuery{
		Query: "JWT none algorithm bypass",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := resultNames(results); len(got) != 1 || got[0] != "jwt-attack-methodology" {
		t.Fatalf("results = %v, want only jwt-attack-methodology", got)
	}
}

func TestSearch_ChineseJWTAlgorithmConfusionMatchesEquivalentEnglishConcept(t *testing.T) {
	db := setupTestDB(t)

	if err := InsertResource(db, Resource{
		Type: "skill", Name: "jwt-attack-methodology", Source: "builtin",
		FilePath: "skills/jwt-attack-methodology/SKILL.md", Category: "exploit",
		Tags:        "jwt,algorithm confusion",
		Description: "JWT algorithm confusion attack methodology.",
		Body:        "Validate RS256 and HS256 signature handling.",
	}); err != nil {
		t.Fatal(err)
	}

	results, _, err := Search(db, SearchQuery{
		Query: "JWT 算法混淆",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := resultNames(results); len(got) != 1 || got[0] != "jwt-attack-methodology" {
		t.Fatalf("results = %v, want jwt-attack-methodology", got)
	}
}

func TestSearch_RejectsQueriesWithTooManySemanticGroups(t *testing.T) {
	db := setupTestDB(t)

	_, _, err := Search(db, SearchQuery{
		Query: "alpha bravo charlie delta echo foxtrot golf hotel india",
		Type:  "skill",
		Limit: 10,
	})
	if err == nil {
		t.Fatal("expected an explicit query complexity error")
	}
	if !strings.Contains(err.Error(), "too many search concepts") {
		t.Fatalf("error = %q, want query complexity diagnostic", err)
	}
}

func TestPlanQuery_RejectsOversizedRawQueryAndExposesContractVersion(t *testing.T) {
	if _, err := PlanQuery(strings.Repeat("a", 257)); err == nil || !strings.Contains(err.Error(), "query too long") {
		t.Fatalf("oversized query error = %v, want explicit query too long error", err)
	}

	plan, err := PlanQuery("JWT")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Version != SearchContractVersion {
		t.Fatalf("plan version = %q, want %q", plan.Version, SearchContractVersion)
	}
}

func TestSecurityConceptRegistryRejectsMoreThanSixAliases(t *testing.T) {
	_, err := buildConceptAliasIndex([]SecurityConcept{{
		ID:      "oversized",
		Aliases: []string{"one", "two", "three", "four", "five", "six", "seven"},
		Role:    ConceptRoleIdentity,
	}})
	if err == nil || !strings.Contains(err.Error(), "at most 6 aliases") {
		t.Fatalf("registry error = %v, want alias limit rejection", err)
	}
}

func TestSecurityConceptRegistryRejectsAliasesSharedByDifferentConcepts(t *testing.T) {
	_, err := buildConceptAliasIndex([]SecurityConcept{
		{ID: "first", Aliases: []string{"shared alias"}, Role: ConceptRoleIdentity},
		{ID: "second", Aliases: []string{" SHARED  ALIAS "}, Role: ConceptRoleTopic},
	})
	if err == nil || !strings.Contains(err.Error(), "shared by concepts") {
		t.Fatalf("registry error = %v, want cross-concept alias rejection", err)
	}
}

func TestPlanQuery_PreservesProductIdentityWithoutCountingCJKIndexAtomsAsGroups(t *testing.T) {
	plan, err := PlanQuery("asp.net mvc 通用权限管理系统 systemmanage sql注入")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Groups) > maxQueryGroups {
		t.Fatalf("semantic groups = %d, want at most %d: %#v", len(plan.Groups), maxQueryGroups, plan.Groups)
	}

	groups := make(map[string]QueryGroup, len(plan.Groups))
	for _, group := range plan.Groups {
		groups[group.Original] = group
	}
	if _, ok := groups["systemmanage"]; !ok {
		t.Fatalf("SystemManage product identity missing from plan: %#v", plan.Groups)
	}
	if _, ok := groups["通用权限管理系统"]; !ok {
		t.Fatalf("Chinese product description was split into index atoms: %#v", plan.Groups)
	}
	foundSQLInjection := false
	for _, group := range plan.Groups {
		if group.ConceptID == "sql_injection" {
			foundSQLInjection = true
			break
		}
	}
	if !foundSQLInjection {
		t.Fatalf("SQL injection concept missing from plan: %#v", plan.Groups)
	}
}

func TestPlanQuery_MergesRepeatedProductAliasesIntoOneSemanticGroup(t *testing.T) {
	plan, err := PlanQuery("learun 力软 通用权限管理系统")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Groups) != 2 {
		t.Fatalf("semantic groups = %#v, want Learun identity plus product description", plan.Groups)
	}
	product := plan.Groups[0]
	if product.ConceptID != "learun" || !product.Anchor {
		t.Fatalf("product group = %#v, want anchored Learun concept", product)
	}
	if !contains(product.Alternatives, "learun") || !contains(product.Alternatives, "力软") {
		t.Fatalf("Learun aliases = %v, want learun and 力软", product.Alternatives)
	}
	if plan.Groups[1].Original != "通用权限管理系统" {
		t.Fatalf("remaining group = %#v, want complete Chinese product description", plan.Groups[1])
	}
}

func TestBuildPinyinFallbackTransliteratesOnlyUnknownHanContext(t *testing.T) {
	plan, err := PlanQuery("天擎 sql注入")
	if err != nil {
		t.Fatal(err)
	}
	fallback, ok := BuildPinyinFallback(plan)
	if !ok {
		t.Fatal("expected a pinyin fallback")
	}
	if fallback.Query != "tianqing sql注入" {
		t.Fatalf("fallback query = %q", fallback.Query)
	}
	if len(fallback.Transliterations) != 1 || fallback.Transliterations[0].From != "天擎" || fallback.Transliterations[0].To != "tianqing" {
		t.Fatalf("transliterations = %#v", fallback.Transliterations)
	}
}

func TestBuildPinyinFallbackRejectsProtectedAndMixedGroups(t *testing.T) {
	for _, query := range []string{"CVE-2021-32799", "v2.0 天擎/api", "天"} {
		plan, err := PlanQuery(query)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := BuildPinyinFallback(plan); ok {
			t.Fatalf("query %q unexpectedly produced a pinyin fallback", query)
		}
	}
}

func TestSearch_JWTAuthenticationBypassRanksCanonicalSkillFirst(t *testing.T) {
	db := setupTestDB(t)

	resources := []Resource{
		{
			Type: "skill", Name: "jwt-attack-methodology", Source: "builtin",
			FilePath: "skills/jwt-attack-methodology/SKILL.md", Category: "exploit",
			Tags:        "jwt,authentication,token",
			Description: "JWT Token 攻击方法论，覆盖 alg:none 绕过和签名验证。",
			Body:        "认证绕过、算法混淆和 Claims 篡改。" + strings.Repeat(" general token guidance", 200),
		},
		{
			Type: "skill", Name: "cookie-analysis", Source: "builtin",
			FilePath: "skills/cookie-analysis/SKILL.md", Category: "exploit",
			Tags:        "cookie,authentication,bypass",
			Description: "Cookie authentication bypass; JWT tokens should use another skill.",
			Body:        "Cookie forgery and authentication bypass workflow.",
		},
		{
			Type: "skill", Name: "java-auth-config-audit", Source: "builtin",
			FilePath: "skills/java-auth-config-audit/SKILL.md", Category: "code-audit",
			Tags:        "java,jwt,authentication bypass",
			Description: "Java authentication bypass and JWT source audit.",
			Body:        "Review authentication bypass filters and JWT claims.",
		},
	}
	for _, resource := range resources {
		if err := InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 40; i++ {
		if err := InsertResource(db, Resource{
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

	results, _, err := Search(db, SearchQuery{
		Query: "JWT authentication bypass",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "jwt-attack-methodology" {
		t.Fatalf("top result = %v, want jwt-attack-methodology", resultNames(results))
	}
}

func TestSearch_JavaJWTSourceAuditRanksJavaSkillBeforeGenericJWT(t *testing.T) {
	db := setupTestDB(t)

	for _, resource := range []Resource{
		{
			Type: "skill", Name: "java-auth-config-audit", Source: "builtin",
			FilePath: "skills/java-auth-config-audit/SKILL.md", Category: "code-audit",
			Tags:        "java,jwt,source,audit",
			Description: "Java JWT source audit for authentication configuration.",
			Body:        "Inspect Java source and JWT validation.",
		},
		{
			Type: "skill", Name: "jwt-attack-methodology", Source: "builtin",
			FilePath: "skills/jwt-attack-methodology/SKILL.md", Category: "exploit",
			Tags:        "jwt,java,source,audit",
			Description: "Generic JWT attacks with a short Java source audit note.",
			Body:        "JWT source audit reference for Java targets.",
		},
	} {
		if err := InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}

	results, _, err := Search(db, SearchQuery{
		Query: "Java JWT source audit",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "java-auth-config-audit" {
		t.Fatalf("top result = %v, want java-auth-config-audit", resultNames(results))
	}
}

func TestSearch_PHPJWTConfigurationAuditRanksPHPSkillBeforeGenericJWT(t *testing.T) {
	db := setupTestDB(t)

	for _, resource := range []Resource{
		{
			Type: "skill", Name: "php-auth-config-audit", Source: "builtin",
			FilePath: "skills/php-auth-config-audit/SKILL.md", Category: "code-audit",
			Tags:        "php,jwt,configuration,audit",
			Description: "PHP JWT configuration audit.",
			Body:        "Inspect PHP authentication configuration and JWT validation.",
		},
		{
			Type: "skill", Name: "jwt-attack-methodology", Source: "builtin",
			FilePath: "skills/jwt-attack-methodology/SKILL.md", Category: "exploit",
			Tags:        "jwt,php,configuration,audit",
			Description: "Generic JWT attacks with a PHP configuration audit note.",
			Body:        "JWT configuration audit reference for PHP targets.",
		},
	} {
		if err := InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}

	results, _, err := Search(db, SearchQuery{
		Query: "PHP JWT configuration audit",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "php-auth-config-audit" {
		t.Fatalf("top result = %v, want php-auth-config-audit", resultNames(results))
	}
}

func TestSearch_SQLiRanksCanonicalSQLInjectionMethodologyFirst(t *testing.T) {
	db := setupTestDB(t)

	for _, resource := range []Resource{
		{
			Type: "skill", Name: "sql-injection-methodology", Source: "builtin",
			FilePath: "skills/sql-injection-methodology/SKILL.md", Category: "exploit",
			Tags:        "sql injection,database,web",
			Description: "SQL injection exploitation methodology.",
			Body:        "Union, error, boolean and time based SQL injection.",
		},
		{
			Type: "skill", Name: "sqlmap-advanced", Source: "builtin",
			FilePath: "skills/sqlmap-advanced/SKILL.md", Category: "tool",
			Tags:        "sqli,sqlmap",
			Description: "Advanced SQLi automation with sqlmap.",
			Body:        "SQLi tamper scripts and automation.",
		},
	} {
		if err := InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}

	results, _, err := Search(db, SearchQuery{
		Query: "SQLi",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "sql-injection-methodology" {
		t.Fatalf("top result = %v, want sql-injection-methodology", resultNames(results))
	}
}

func TestSearch_LinuxPrivilegeEscalationRanksLinuxPostExploitSkillFirst(t *testing.T) {
	db := setupTestDB(t)

	for _, resource := range []Resource{
		{
			Type: "skill", Name: "post-exploit-linux", Source: "builtin",
			FilePath: "skills/post-exploit-linux/SKILL.md", Category: "postexploit",
			Tags:        "linux,privesc,提权",
			Description: "Linux 后渗透与提权方法论。",
			Body:        "sudo、SUID、capabilities 与内核提权。",
		},
		{
			Type: "skill", Name: "aws-iam-privesc", Source: "builtin",
			FilePath: "skills/aws-iam-privesc/SKILL.md", Category: "cloud",
			Tags:        "aws,iam,privilege escalation",
			Description: "AWS privilege escalation techniques.",
			Body:        "Includes a Linux EC2 example.",
		},
	} {
		if err := InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}

	results, _, err := Search(db, SearchQuery{
		Query: "privilege escalation linux",
		Type:  "skill",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "post-exploit-linux" {
		t.Fatalf("top result = %v, want post-exploit-linux", resultNames(results))
	}
}

func TestRankCandidates_UsesStableResourceIDAsFinalTieBreaker(t *testing.T) {
	plan, err := PlanQuery("JWT")
	if err != nil {
		t.Fatal(err)
	}
	results := []SearchResult{
		{Resource: Resource{Type: "skill", Name: "jwt-guide", Source: "team", Tags: "jwt"}, Score: -1},
		{Resource: Resource{Type: "skill", Name: "jwt-guide", Source: "builtin", Tags: "jwt"}, Score: -1},
	}

	rankCandidates(plan, results)

	if got, want := StableID(results[0].Resource), "absec://builtin/skill/jwt-guide"; got != want {
		t.Fatalf("top stable ID = %q, want %q", got, want)
	}
}

func TestRankCandidates_NormalizesTagSeparatorsForConceptCoverage(t *testing.T) {
	plan, err := PlanQuery("JWT bypass")
	if err != nil {
		t.Fatal(err)
	}
	results := []SearchResult{
		{Resource: Resource{Type: "skill", Name: "generic-guide", Source: "builtin", Tags: "jwt"}, Score: -1},
		{Resource: Resource{Type: "skill", Name: "focused-guide", Source: "team", Tags: "jwt,bypass"}, Score: -1},
	}

	rankCandidates(plan, results)

	if got := results[0].Name; got != "focused-guide" {
		t.Fatalf("top result = %q, want comma-separated tag coverage to rank focused-guide first", got)
	}
}

func resultNames(results []SearchResult) []string {
	names := make([]string, len(results))
	for i, result := range results {
		names[i] = result.Name
	}
	return names
}

func TestSearch_DefaultVisibilityExcludesDisabledResources(t *testing.T) {
	db := setupTestDB(t)
	if err := InsertResource(db, Resource{
		Type: "skill", Name: "disabled-agent-knowledge", Source: "custom",
		Description: "must remain hidden from agent search",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE resources SET enabled = 0 WHERE name = ?", "disabled-agent-knowledge"); err != nil {
		t.Fatal(err)
	}

	results, total, err := Search(db, SearchQuery{Query: "agent", Type: "skill", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 || len(results) != 0 {
		t.Fatalf("disabled resource leaked into default search: total=%d results=%d", total, len(results))
	}
}

func TestSearch_WithCategoryFilter(t *testing.T) {
	db := setupTestDB(t)

	InsertResource(db, Resource{
		Type: "skill", Name: "nmap-scan", Source: "builtin",
		FilePath: "skills/nmap/SKILL.md", Category: "recon",
		Tags: "scan", Description: "Nmap scanning",
		Body: "Network scanning with nmap",
	})
	InsertResource(db, Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		FilePath: "skills/sqli/SKILL.md", Category: "exploit",
		Tags: "sqli", Description: "SQL Injection",
		Body: "SQL Injection techniques",
	})

	results, _, err := Search(db, SearchQuery{
		Query:    "scan",
		Type:     "skill",
		Category: "recon",
		Limit:    10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Name != "nmap-scan" {
		t.Errorf("expected only nmap-scan with category filter, got %v", results)
	}
}

func TestListByType_ReturnsTotalAndOffset(t *testing.T) {
	db := setupTestDB(t)
	for _, name := range []string{"skill-a", "skill-b", "skill-c"} {
		if err := InsertResource(db, Resource{
			Type: "skill", Name: name, Source: "builtin",
			Category: "exploit", Description: name,
		}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := ListByType(db, ListQuery{Type: "skill", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 3 {
		t.Errorf("total = %d, want 3", result.Total)
	}
	if len(result.Items) != 2 {
		t.Errorf("items = %d, want 2", len(result.Items))
	}
	result2, err := ListByType(db, ListQuery{Type: "skill", Offset: 2, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result2.Total != 3 {
		t.Errorf("total with offset = %d, want 3", result2.Total)
	}
	if len(result2.Items) != 1 {
		t.Errorf("items with offset = %d, want 1", len(result2.Items))
	}
}

func TestListByType_AllTypes(t *testing.T) {
	db := setupTestDB(t)
	InsertResource(db, Resource{
		Type: "skill", Name: "test-skill", Source: "builtin",
		Category: "exploit", Description: "a skill",
	})
	InsertResource(db, Resource{
		Type: "dict", Name: "test-dict", Source: "builtin",
		Category: "password", Description: "a dict",
	})
	// Empty Type = list all types
	result, err := ListByType(db, ListQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total < 2 {
		t.Errorf("total = %d, want >= 2", result.Total)
	}
	types := map[string]bool{}
	for _, item := range result.Items {
		types[item.Type] = true
	}
	if !types["skill"] || !types["dict"] {
		t.Errorf("expected both skill and dict types, got %v", types)
	}
}

func TestSearch_ReturnsTotal(t *testing.T) {
	db := setupTestDB(t)
	for _, name := range []string{"sql-injection-basic", "sql-injection-advanced", "sql-injection-blind"} {
		InsertResource(db, Resource{
			Type: "skill", Name: name, Source: "builtin",
			Category: "exploit", Description: "SQL injection technique " + name,
			Body: "SQL injection attack",
		})
	}
	results, total, err := Search(db, SearchQuery{Query: "SQL injection", Type: "skill", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(results) != 2 {
		t.Errorf("results = %d, want 2", len(results))
	}
}

func insertVuln(t *testing.T, db *sql.DB, name, category, severity, product string) {
	t.Helper()
	metadata := fmt.Sprintf(`{"severity":"%s","product":"%s","vendor":"TestVendor"}`, severity, product)
	desc := fmt.Sprintf("vuln %s %s", name, product)
	body := fmt.Sprintf("vuln body %s", name)
	res, err := db.Exec(`INSERT OR REPLACE INTO resources
		(type,name,source,file_path,category,tags,description,body,metadata)
		VALUES ('vuln',?,'builtin','test.md',?,'rce',?,?,?)`,
		name, category, desc, body, metadata)
	if err != nil {
		t.Fatalf("insertVuln %s: %v", name, err)
	}
	id, _ := res.LastInsertId()
	if err := IndexFTS(db, id, name, desc, "rce", category, body); err != nil {
		t.Fatalf("insertVuln IndexFTS %s: %v", name, err)
	}
}

func TestSearch_ExcludesVulnByDefault(t *testing.T) {
	db := setupTestDB(t)
	// Insert a skill and a vuln that both match "injection"
	InsertResource(db, Resource{
		Type: "skill", Name: "sql-injection", Source: "builtin",
		Category: "exploit", Description: "SQL Injection techniques",
		Body: "SQL injection attack details",
	})
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")

	// Search without specifying type — vuln should be excluded
	results, _, err := Search(db, SearchQuery{Query: "vuln", Limit: 10})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	for _, r := range results {
		if r.Type == "vuln" {
			t.Errorf("expected no vuln results in default search, got %q", r.Name)
		}
	}
}

func TestSearch_IncludesVulnWithExplicitType(t *testing.T) {
	db := setupTestDB(t)
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")

	results, total, err := Search(db, SearchQuery{Query: "vuln", Type: "vuln", Limit: 10})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if total == 0 {
		t.Fatal("expected vuln results with explicit type, got 0")
	}
	if results[0].Type != "vuln" {
		t.Errorf("expected type vuln, got %q", results[0].Type)
	}
}

func TestSearch_VulnKeepsLegacyBM25Ordering(t *testing.T) {
	db := setupTestDB(t)
	for _, resource := range []Resource{
		{
			Type: "vuln", Name: "jwt-vulnerability-guide", Source: "builtin",
			Tags:        "reference",
			Description: "General token vulnerability reference.",
			Body:        strings.Repeat("unrelated background ", 800) + " authentication bypass",
		},
		{
			Type: "vuln", Name: "CVE-2026-0001", Source: "builtin",
			Tags:        "jwt,authentication,bypass",
			Description: "JWT authentication bypass",
			Body:        "JWT authentication bypass",
		},
	} {
		if err := InsertResource(db, resource); err != nil {
			t.Fatal(err)
		}
	}

	results, _, err := Search(db, SearchQuery{
		Query: "JWT authentication bypass",
		Type:  "vuln",
		Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[0].Name != "CVE-2026-0001" {
		t.Fatalf("vuln results = %v, want legacy BM25 to keep CVE-2026-0001 first", resultNames(results))
	}
}

func TestSearch_SeverityFilter(t *testing.T) {
	db := setupTestDB(t)
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")
	insertVuln(t, db, "CVE-2023-0001", "rce", "LOW", "SomeProduct")

	results, total, err := Search(db, SearchQuery{
		Query:    "vuln",
		Type:     "vuln",
		Severity: "CRITICAL",
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Name != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %q", results[0].Name)
	}
}

func TestSearch_ProductFilter(t *testing.T) {
	db := setupTestDB(t)
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")
	insertVuln(t, db, "CVE-2023-0002", "rce", "HIGH", "OpenSSL")

	results, total, err := Search(db, SearchQuery{
		Query:   "vuln",
		Type:    "vuln",
		Product: "OpenSSL",
		Limit:   10,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Name != "CVE-2023-0002" {
		t.Errorf("expected CVE-2023-0002, got %q", results[0].Name)
	}
}

func TestListByType_ExcludesVulnByDefault(t *testing.T) {
	db := setupTestDB(t)
	InsertResource(db, Resource{
		Type: "skill", Name: "test-skill", Source: "builtin",
		Category: "exploit", Description: "a skill",
	})
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")

	// List without type — vuln should be excluded
	result, err := ListByType(db, ListQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range result.Items {
		if item.Type == "vuln" {
			t.Errorf("expected no vuln in default list, got %q", item.Name)
		}
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1 (only skill)", result.Total)
	}
}

func TestListByType_VulnWithSeverityFilter(t *testing.T) {
	db := setupTestDB(t)
	insertVuln(t, db, "CVE-2021-44228", "rce", "CRITICAL", "Apache Log4j")
	insertVuln(t, db, "CVE-2023-0001", "rce", "LOW", "SomeProduct")

	result, err := ListByType(db, ListQuery{
		Type:     "vuln",
		Severity: "CRITICAL",
		Limit:    50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Errorf("total = %d, want 1", result.Total)
	}
	if len(result.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(result.Items))
	}
	if result.Items[0].Name != "CVE-2021-44228" {
		t.Errorf("expected CVE-2021-44228, got %q", result.Items[0].Name)
	}
}

func TestSearch_ConcurrentReaders(t *testing.T) {
	db := setupTestDB(t)
	for i := 0; i < 8; i++ {
		if err := InsertResource(db, Resource{
			Type:        "skill",
			Name:        fmt.Sprintf("skill-%d", i),
			Source:      "builtin",
			Description: "SQL injection concurrent search",
			Body:        "SQL injection concurrent search body",
		}); err != nil {
			t.Fatal(err)
		}
	}

	const workers = 16
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results, _, err := Search(db, SearchQuery{
				Query: "SQL injection",
				Type:  "skill",
				Limit: 10,
			})
			if err != nil {
				errCh <- err
				return
			}
			if len(results) == 0 {
				errCh <- fmt.Errorf("expected search results")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
