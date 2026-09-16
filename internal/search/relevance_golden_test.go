package search

import (
	"database/sql"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wgpsec/context1337/internal/storage"
)

func openRuntimeCorpus(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join("..", "..", "data", "runtime", "runtime.db")
	if _, err := os.Stat(dbPath); err != nil {
		t.Skipf("runtime corpus is not available: %v", err)
	}
	db, err := storage.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func openCandidateCorpus(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := os.Getenv("CONTEXT1337_CORPUS_DB")
	if dbPath == "" {
		t.Skip("CONTEXT1337_CORPUS_DB is not set")
	}
	db, err := storage.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestRuntimeCorpusCanonicalSkillGoldenRanking(t *testing.T) {
	db := openRuntimeCorpus(t)

	tests := []struct {
		query   string
		wantTop string
	}{
		{"JWT algorithm confusion", "jwt-attack-methodology"},
		{"JWT none algorithm bypass", "jwt-attack-methodology"},
		{"JWT authentication bypass", "jwt-attack-methodology"},
		{"JWT 算法混淆", "jwt-attack-methodology"},
		{"SQL injection", "sql-injection-methodology"},
		{"file upload webshell", "file-upload-methodology"},
		{"OAuth redirect URI", "oauth-sso-attack"},
		{"Java deserialization", "java-deserialization-methodology"},
	}

	for _, test := range tests {
		t.Run(test.query, func(t *testing.T) {
			results, _, err := Search(db, SearchQuery{
				Query: test.query,
				Type:  "skill",
				Limit: 150,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(results) == 0 || results[0].Name != test.wantTop {
				t.Fatalf("top results = %v, want %s", resultNames(results), test.wantTop)
			}
		})
	}
}

func TestRuntimeCorpusCanonicalSearchP95(t *testing.T) {
	if raceEnabled {
		t.Skip("wall-clock performance threshold is not meaningful with race instrumentation")
	}

	db := openRuntimeCorpus(t)

	queries := []string{
		"JWT algorithm confusion",
		"JWT none algorithm bypass",
		"SQL injection",
		"file upload webshell",
		"OAuth redirect URI",
		"Java deserialization",
	}
	for _, query := range queries {
		if _, _, err := Search(db, SearchQuery{Query: query, Type: "skill", Limit: 150}); err != nil {
			t.Fatal(err)
		}
	}

	durations := make([]time.Duration, 0, 120)
	for i := 0; i < 120; i++ {
		query := queries[i%len(queries)]
		started := time.Now()
		if _, _, err := Search(db, SearchQuery{Query: query, Type: "skill", Limit: 150}); err != nil {
			t.Fatal(err)
		}
		durations = append(durations, time.Since(started))
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	p95 := durations[(len(durations)*95+99)/100-1]
	t.Logf("canonical search p95=%s", p95)
	if p95 > 100*time.Millisecond {
		t.Fatalf("canonical search p95 = %s, want <= 100ms", p95)
	}
}

func TestRuntimeCorpusChineseAliasGoldenRecall(t *testing.T) {
	db := openRuntimeCorpus(t)

	vulns, _, err := Search(db, SearchQuery{
		Query: "积木报表",
		Type:  "vuln",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(resultNames(vulns), "CVE-2023-1454") {
		t.Fatalf("积木报表 results = %v, want CVE-2023-1454", resultNames(vulns))
	}

	dicts, _, err := Search(db, SearchQuery{
		Query: "密码字典 弱口令 常用密码",
		Type:  "dict",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(dicts) == 0 || !strings.HasPrefix(dicts[0].Name, "auth/password/") {
		t.Fatalf("password dictionary results = %v, want auth/password canonical result", resultNames(dicts))
	}
}

func TestCandidateCorpusSystemManageAssessmentGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{
		Query: "systemmanage sql注入",
		Type:  "skill",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "aspnet-mvc-admin-assessment" {
		t.Fatalf("systemmanage results = %v, want aspnet-mvc-admin-assessment first", resultNames(results))
	}
}

func TestCandidateCorpusJeecgJmreportAssessmentGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{
		Query: "jeecg-boot jmreport 未授权",
		Type:  "skill",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "jeecg-jmreport-assessment" {
		t.Fatalf("jeecg jmreport results = %v, want jeecg-jmreport-assessment first", resultNames(results))
	}
}

func TestCandidateCorpusNROSGSIAssessmentGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{
		Query: "久其 nros gsi 未授权",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "nros-gsi-assessment" {
		t.Fatalf("NROS GSI results = %v, want nros-gsi-assessment first", resultNames(results))
	}
}

func TestCandidateCorpusPHPCMSAssessmentGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{Query: "phpcms", Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "phpcms-assessment" {
		t.Fatalf("PHPCMS results = %v, want phpcms-assessment first", resultNames(results))
	}
}

func TestCandidateCorpusPHPAttackChainGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{
		Query: "php 反序列化 文件包含 日志投毒",
		Type:  "skill",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "php-attack-chain-assessment" {
		t.Fatalf("PHP attack-chain results = %v, want php-attack-chain-assessment first", resultNames(results))
	}
}

func TestCandidateCorpusYiiRequestForgeryGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{
		Query: "yii 反序列化 csrf 伪造",
		Type:  "skill",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "yii-request-forgery-assessment" {
		t.Fatalf("Yii request-forgery results = %v, want yii-request-forgery-assessment first", resultNames(results))
	}
}

func TestCandidateCorpusWangshenEndpointAssessmentGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{
		Query: "网神 终端安全 反序列化",
		Type:  "skill",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "wangshen-endpoint-security-assessment" {
		t.Fatalf("Wangshen endpoint results = %v, want wangshen-endpoint-security-assessment first", resultNames(results))
	}
}

func TestCandidateCorpusChineseUsernameDictionaryGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{
		Query: "chinese china",
		Type:  "dict",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "auth/username/cn-email.txt" {
		t.Fatalf("Chinese username dictionary results = %v, want auth/username/cn-email.txt first", resultNames(results))
	}
}

func TestCandidateCorpusJmreportPrivilegeEscalationGoldenRecall(t *testing.T) {
	db := openCandidateCorpus(t)

	results, _, err := Search(db, SearchQuery{
		Query: "cve-2024-44893 jmreport",
		Type:  "vuln",
		Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) == 0 || results[0].Name != "CVE-2024-44893" {
		t.Fatalf("JimuReport CVE results = %v, want CVE-2024-44893 first", resultNames(results))
	}
}

func TestCandidateCorpusVulnerabilityAliasesStayExcludedWithoutType(t *testing.T) {
	db := openCandidateCorpus(t)

	for _, query := range []string{"queryfieldbysql", "积木报表"} {
		results, _, err := Search(db, SearchQuery{Query: query, Limit: 20})
		if err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		if len(results) != 0 {
			t.Fatalf("query %q returned %v without type=vuln", query, resultNames(results))
		}
	}
}

func TestCandidateCorpusUnsupportedVulnerabilityAndDictionaryQueriesStayEmpty(t *testing.T) {
	db := openCandidateCorpus(t)

	for _, query := range []struct {
		query string
		typ   string
	}{
		{"nfine 快速开发平台 getgridjson", "vuln"},
		{"phpcms 9.6.0", "vuln"},
		{"trs wcm 拓尔思", "vuln"},
		{"政府 默认口令", "dict"},
	} {
		results, _, err := Search(db, SearchQuery{Query: query.query, Type: query.typ, Limit: 20})
		if err != nil {
			t.Fatalf("query %q type=%s: %v", query.query, query.typ, err)
		}
		if len(results) != 0 {
			t.Fatalf("query %q type=%s returned %v; unsupported content must stay empty", query.query, query.typ, resultNames(results))
		}
	}
}
