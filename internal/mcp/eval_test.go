package mcp

// Search quality and latency evaluation over the real AboutSecurity corpus.
//
// This is a measurement harness, not a regression test: it is skipped unless
// CONTEXT1337_EVAL_DB points at a finalized builtin.db, because the numbers it
// prints are only meaningful against the shipped corpus.
//
// Run it with a builtin.db next to a data dir that holds (or symlinks) the
// AboutSecurity tree, so the labels below can be re-derived from the corpus:
//
//	CONTEXT1337_EVAL_DB=/tmp/eval/builtin.db go test -tags "fts5 sqlite_json" \
//	    -run 'TestSearch(Eval|LatencyProfile)' -v ./internal/mcp/
//
// Every expectation here was written by reading the corpus, not by running the
// search and recording whatever came back. That distinction is what makes the
// numbers usable as a baseline: a harness that grades the code against its own
// output can only ever report "unchanged". An earlier draft of this file got
// this wrong and asserted on names that look plausible but do not exist in the
// corpus (WEBLOGIC-CVE-2020-14882 — the real row is bare CVE-2020-14882), which
// produced five bogus MISSes. Ground truth must come from the data.
//
// Names in the index are the vendored filenames, so the labels follow the
// corpus rather than the vendor's convention: vulnerability rows are named
// either `CVE-YYYY-NNNNN`, `S2-0NN`, or `<VENDOR>-<THING>`, and a query for a
// vendor only reaches the bare-CVE rows because the vendor name appears in the
// body, not the row name.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wgpsec/context1337/internal/storage"
	"github.com/wgpsec/context1337/internal/usage"
)

// evalCase is one labeled query.
type evalCase struct {
	name string
	// query is sent verbatim.
	query string
	// typ restricts the search, mirroring how an agent would call the tool.
	typ string
	// wantAny requires at least one of these names in the returned page. These
	// are resources a competent answer must surface.
	wantAny []string
	// forbid names that must not appear: they are known distractors.
	forbid []string
	// minTotal is a lower bound on the reported total, used where the corpus
	// size is known and a shrunken total means silent recall loss.
	minTotal int
	// wantTotal pins the reported total exactly, for queries whose match count
	// is known from the corpus. This is the assertion that catches a candidate
	// window clipping the result set: a cap does not change which rows are
	// returned on page one, only the total a client pages against, and
	// minTotal would hide it whenever the cap sits above the bound.
	wantTotal int
	// status is the expected SearchResult.Status, when the pipeline is supposed
	// to classify the query rather than just answer it.
	status string
}

func evalService(t *testing.T) *Service {
	t.Helper()
	dbPath := os.Getenv("CONTEXT1337_EVAL_DB")
	if dbPath == "" {
		t.Skip("CONTEXT1337_EVAL_DB not set; skipping corpus evaluation")
	}
	db, err := storage.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("open eval db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewService(db, filepath.Dir(dbPath), usage.NewCollector())
}

func runEvalCase(t *testing.T, svc *Service, tc evalCase) (names []string, res *SearchResult, elapsed time.Duration) {
	t.Helper()
	limit := 50
	want := tc.minTotal
	if tc.wantTotal > want {
		want = tc.wantTotal
	}
	if want > limit {
		limit = want * 2
	}
	start := time.Now()
	res, err := svc.Search(context.Background(), SearchInput{
		Query: tc.query, Type: tc.typ, Limit: limit,
	})
	elapsed = time.Since(start)
	if err != nil {
		t.Fatalf("%s: search error: %v", tc.name, err)
	}
	if res == nil {
		t.Fatalf("%s: nil result", tc.name)
	}
	for _, item := range res.Items {
		names = append(names, item.Name)
	}
	return names, res, elapsed
}

func TestSearchEval(t *testing.T) {
	svc := evalService(t)

	cases := []evalCase{
		// --- Product/vendor identification: the CVE-shaped question an agent
		// asks when it has fingerprinted a target. The vendor name lives in the
		// body, so a named vendor row and its bare-CVE siblings must all be
		// reachable. ---
		{
			name:  "weblogic vulns",
			query: "weblogic",
			typ:   "vuln",
			wantAny: []string{
				"WEBLOGIC-", "CVE-2020-14882", "CVE-2019-2725", "CVE-2020-2551",
			},
			minTotal: 10,
		},
		{
			name:    "struts2 vulns by S2 id",
			query:   "S2-045",
			typ:     "vuln",
			wantAny: []string{"S2-045"},
		},
		{
			name:    "specific CVE lookup",
			query:   "CVE-2021-44228",
			typ:     "vuln",
			wantAny: []string{"CVE-2021-44228", "SOLR-LOG4J-RCE"},
		},
		{
			// A vendor whose only corpus presence is inside body text. vuln
			// search must reach it: this is the "I found a nuxeo box" case.
			name:    "vendor present only in body",
			query:   "nuxeo",
			typ:     "vuln",
			wantAny: []string{"CVE-2018-16341"},
		},

		// --- Chinese technique queries: the primary language of the corpus and
		// of the target user. These exercise the dictionary + bigram path. ---
		{
			// Not "域持久化": that phrase appears nowhere in the corpus, so a
			// no_match there is correct behaviour, not a recall bug. This is
			// the phrasing ad-persistence itself uses.
			name:    "domain persistence in Chinese",
			query:   "域级持久化",
			typ:     "skill",
			wantAny: []string{"ad-persistence"},
		},
		{
			name:    "lateral movement in Chinese",
			query:   "横向移动",
			typ:     "skill",
			wantAny: []string{"ad-acl-abuse", "ad-delegation-attack", "ad-domain-attack", "lateral-movement"},
		},
		{
			name:    "privilege escalation in Chinese",
			query:   "linux 提权",
			typ:     "skill",
			wantAny: []string{"post-exploit-linux", "aws-iam-privesc"},
		},
		{
			name:    "generic persistence in Chinese",
			query:   "持久化",
			typ:     "skill",
			wantAny: []string{"persist-maintain", "ad-persistence"},
		},

		// --- Concept aliasing: the planner is supposed to collapse these
		// synonyms so an agent using either spelling gets the same answers. ---
		{
			name:    "sqli english",
			query:   "sql injection",
			typ:     "skill",
			wantAny: []string{"sql-injection-methodology", "sqlmap-advanced"},
		},
		{
			name:     "sqli chinese alias",
			query:    "sql注入",
			typ:      "skill",
			wantAny:  []string{"sql-injection-methodology", "sqlmap-advanced"},
			minTotal: 1,
		},

		// --- Result-set size: a query whose match count exceeds any candidate
		// window must still report the whole match count. Ranking here is not
		// order-preserving (the relevance trim needs the best score in the list,
		// cross-type diversify needs every type's candidates), so a window that
		// clips the match set makes `total` an artifact of the window rather than
		// the size of the result set. 434 is the count of vuln rows matching
		// "rce"; the counts below come from the corpus, not from running this. ---
		{
			// The widest match set any single term reaches: every vuln row
			// mentions a year, so "1" matches 664 of 664. Also the slowest
			// query in the corpus at 5.4ms, which is what bounds the cost of
			// ranking whole match sets.
			name:      "total is not clipped by the candidate window",
			query:     "1",
			typ:       "vuln",
			minTotal:  664,
			wantTotal: 664,
		},
		{
			name:      "large typed match set keeps its real total",
			query:     "rce",
			typ:       "vuln",
			wantAny:   []string{"CVE-"},
			wantTotal: 434,
		},
		{
			name:    "deserialization chinese alias",
			query:   "反序列化",
			typ:     "skill",
			wantAny: []string{"deserialization-methodology", "java-deserialization-methodology"},
		},

		// --- Wordlists: distinct from technique search. ---
		{
			name:    "jwt secret wordlist",
			query:   "jwt secret",
			typ:     "dict",
			wantAny: []string{"auth/jwt/jwt-secret.txt"},
		},
		{
			name:    "password dictionary",
			query:   "密码 字典",
			typ:     "dict",
			wantAny: []string{"auth/password/"},
		},
		{
			name:    "port dictionary",
			query:   "port",
			typ:     "dict",
			wantAny: []string{"port/"},
		},

		// --- Payload lookup: an agent that found an injection point wants the
		// payload file, not an essay. ---
		{
			name:    "xss payload",
			query:   "xss payload",
			typ:     "payload",
			wantAny: []string{"xss/"},
		},
		{
			name:    "lfi linux path payload",
			query:   "lfi linux path",
			typ:     "payload",
			wantAny: []string{"lfi/linux-path.txt", "lfi/linux.txt"},
		},
		{
			name:    "ssrf payload",
			query:   "ssrf",
			typ:     "payload",
			wantAny: []string{"ssrf/payload.txt"},
		},

		// --- Long dictionary terms: the compound terms that live in
		// SecurityTerms and are expected to survive the whole pipeline. ---
		{
			name:    "compound dict term ssti",
			query:   "服务器端模板注入",
			typ:     "vuln",
			wantAny: []string{"CVE-2018-16341"},
		},
		{
			name:    "compound dict term command injection",
			query:   "操作系统命令注入",
			typ:     "vuln",
			wantAny: []string{"CVE-2020-13925"},
		},

		// --- Named products, frameworks and tooling. A word the planner cannot
		// classify makes a prose question produce no retry at all, so these
		// concepts are what makes the retry mechanism reachable for the way an
		// agent actually asks. Each expectation is a resource a competent answer
		// to that question must surface. ---
		{
			name:    "kerberoasting by name",
			query:   "kerberoasting",
			typ:     "skill",
			wantAny: []string{"kerberos-pentesting", "ad-domain-attack"},
		},
		{
			name:    "lateral movement by name",
			query:   "横向移动",
			typ:     "skill",
			wantAny: []string{"impacket-toolkit", "lateral-movement", "ad-domain-attack"},
		},
		{
			name:    "redis by name",
			query:   "redis",
			typ:     "skill",
			wantAny: []string{"redis-attack", "redis-pentesting"},
		},
		{
			name:    "docker escape by name",
			query:   "docker 逃逸",
			typ:     "skill",
			wantAny: []string{"docker-pentesting", "cdk-escape"},
		},
		{
			name:    "sqlmap by name",
			query:   "sqlmap",
			typ:     "skill",
			wantAny: []string{"sqlmap-advanced", "sql-injection-methodology"},
		},

		// --- Alias shape: an alias that contains every token of a narrower alias
		// in the same concept is a redundant OR branch, and FTS5 scores a row once
		// per matching branch. That inflates the best score, which tightens the
		// relevance cutoff and shrinks the reported total. These pin the totals
		// measured with a single alias so a reintroduced compound alias shows up
		// as a number rather than as a slow drift. ---
		{
			name:      "product alias does not inflate bm25",
			query:     "tomcat",
			typ:       "skill",
			minTotal:  17,
			wantTotal: 17,
		},
		{
			name:      "framework alias does not inflate bm25",
			query:     "spring",
			typ:       "skill",
			minTotal:  26,
			wantTotal: 26,
		},

		// --- Adversarial: long natural-language phrasing, which the tool docs
		// explicitly warn against but agents produce anyway. The contract is
		// that this is rejected loudly rather than answered badly. ---
		{
			name:    "verbose natural language",
			query:   "目标是一台 linux 服务器 我已经拿到 webshell 了 接下来怎么提权维持权限",
			typ:     "skill",
			status:  "query_too_complex",
			wantAny: nil,
		},
	}

	type row struct {
		name    string
		latency time.Duration
		hits    int
		recall  string
		verdict string
		ret     int
		total   int
		status  string
	}
	var rows []row

	for _, tc := range cases {
		names, res, elapsed := runEvalCase(t, svc, tc)

		hitCount := 0
		for _, w := range tc.wantAny {
			for _, n := range names {
				if strings.HasPrefix(n, w) {
					hitCount++
					break
				}
			}
		}

		problems := []string{}
		if len(tc.wantAny) > 0 && hitCount == 0 {
			problems = append(problems, "MISS")
		}
		if tc.minTotal > 0 && res.Total < tc.minTotal {
			problems = append(problems, fmt.Sprintf("TOTAL<%d", tc.minTotal))
		}
		if tc.wantTotal > 0 && res.Total != tc.wantTotal {
			problems = append(problems, fmt.Sprintf("TOTAL=%d(want %d)", res.Total, tc.wantTotal))
		}
		if tc.status != "" && res.Status != tc.status {
			problems = append(problems, fmt.Sprintf("STATUS=%s(want %s)", res.Status, tc.status))
		}
		for _, f := range tc.forbid {
			for _, n := range names {
				if strings.HasPrefix(n, f) {
					problems = append(problems, "FORBIDDEN:"+n)
					break
				}
			}
		}
		verdict := "PASS"
		if len(problems) > 0 {
			verdict = strings.Join(problems, ",")
		}

		rows = append(rows, row{
			name: tc.name, latency: elapsed, hits: hitCount,
			recall:  fmt.Sprintf("%d/%d", hitCount, len(tc.wantAny)),
			verdict: verdict, ret: len(names), total: res.Total, status: res.Status,
		})
	}

	fmt.Printf("\n%-38s %9s %6s %7s %7s %-10s %s\n",
		"QUERY", "LATENCY", "RECALL", "TOTAL", "RETURNED", "STATUS", "VERDICT")
	var total time.Duration
	failures := 0
	for _, r := range rows {
		fmt.Printf("%-38s %9s %6s %7d %8d %-10s %s\n",
			r.name, r.latency.Round(time.Millisecond), r.recall, r.total, r.ret, r.status, r.verdict)
		total += r.latency
		if r.verdict != "PASS" {
			failures++
		}
	}
	fmt.Printf("\ncases=%d  total=%s  mean=%s  failures=%d\n\n",
		len(rows), total.Round(time.Millisecond),
		(total / time.Duration(len(rows))).Round(time.Millisecond), failures)
}

// TestSearchRetryEval follows every retry this corpus produces and reports what
// it returns.
//
// The property under test is that a suggestion is worth acting on. The retry
// planner used to carry the caller's unrecognised words into the retry, which
// re-sent the terms that made the query fail: measured here, that returned
// nothing for six of six offered. A suggestion that reproduces the empty result
// is worse than none, because it costs a round trip and reads as if the corpus
// had no answer.
//
// Phrasings are the ones an agent writes in prose, paired with the keyword form
// that demonstrably reaches the corpus. Zero-result and no-concept rows are
// reported rather than failed: a query the planner recognised nothing in is
// supposed to offer nothing (inventing a retry there is the "伪造 retries" the
// v2 closure design rules out), and a genuinely wide query legitimately returns
// zero.
func TestSearchRetryEval(t *testing.T) {
	svc := evalService(t)

	cases := []struct {
		name    string
		query   string
		typ     string
		keyword string
	}{
		{"waf bypass webshell", "怎么绕过 waf 上传 webshell", "", "waf bypass webshell upload"},
		{"webshell to privesc", "拿到 webshell 之后怎么提权", "", "webshell 提权"},
		{"lateral movement", "内网横向移动用什么工具", "", "横向移动"},
		{"sqli how-to", "sql注入 怎么 利用", "", "sql注入"},
		{"redis unauth how-to", "redis 未授权 怎么 利用", "", "redis 未授权"},
		{"kerberoasting", "kerberoasting 怎么 打", "", "kerberoasting"},
		{"delegation vs silver ticket", "域内横向移动 用 白银票据 还是 委派攻击", "", "委派攻击"},
		{"shiro deserialization", "我想打一个 shiro 反序列化", "", "shiro 反序列化"},
		{"actuator", "spring boot actuator 怎么利用", "", "actuator"},
		{"docker escape", "docker 逃逸 怎么做", "", "docker 逃逸"},
		{"mysql udf privesc", "mysql udf 提权 姿势", "", "mysql udf 提权"},
		{"sqlmap blind", "怎么用 sqlmap 跑 盲注", "", "sqlmap 盲注"},
		{"av evasion", "钓鱼邮件 怎么 免杀", "", "免杀"},
		{"rdp bruteforce", "3389 怎么 爆破", "", "3389 爆破"},
		{"tomcat weak creds", "tomcat 弱口令 怎么 打", "", "tomcat 弱口令"},
		{"suid privesc", "linux 提权 suid 怎么 利用", "", "suid 提权"},
		{"port scanning", "如何做 端口 扫描", "", "端口扫描"},
		{"spec flagship case", "getsimilarlist 360 天擎 sqli", "vuln", ""},
	}

	type row struct {
		name     string
		status   string
		retries  int
		usable   int
		dropped  string
		firstHit int
	}
	var rows []row
	offeredTotal, usableTotal := 0, 0

	for _, tc := range cases {
		first, err := svc.Search(context.Background(), SearchInput{Query: tc.query, Type: tc.typ, Limit: 10})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}

		r := row{name: tc.name, status: first.Status, retries: len(first.RetryQueries)}
		if len(first.RetryQueries) > 0 {
			offeredTotal++
			r.dropped = fmt.Sprint(first.RetryQueries[0].DroppedTerms)
			// A retry whose own result set is empty is the failure mode this
			// eval exists to catch.
			for _, retry := range first.RetryQueries {
				followed, err := svc.Search(context.Background(), SearchInput{
					Query: retry.Query, Type: retry.Type, Limit: 5,
				})
				if err != nil {
					t.Fatalf("%s: retry %q: %v", tc.name, retry.Query, err)
				}
				if followed.Status == "matched" && len(followed.Items) > 0 {
					r.usable++
					if r.firstHit == 0 {
						r.firstHit = followed.Total
					}
				}
			}
			if r.usable > 0 {
				usableTotal++
			}
		}
		rows = append(rows, r)
	}

	fmt.Printf("\n%-32s %-10s %4s %7s %8s %s\n",
		"PHRASING", "STATUS", "RTY", "USABLE", "HITS", "DROPPED")
	for _, r := range rows {
		usable := "-"
		if r.retries > 0 {
			usable = fmt.Sprintf("%d/%d", r.usable, r.retries)
		}
		dropped := r.dropped
		if dropped == "" {
			dropped = "-"
		}
		fmt.Printf("%-32s %-10s %4d %7s %8d %s\n",
			r.name, r.status, r.retries, usable, r.firstHit, dropped)
	}
	fmt.Printf("\nphrasings=%d  offered a retry=%d  retry that returned rows=%d\n\n",
		len(rows), offeredTotal, usableTotal)
}

// TestSearchLatencyProfile reports where time goes across query shapes, so a
// change can be attributed to a query class rather than a single number.
func TestSearchLatencyProfile(t *testing.T) {
	svc := evalService(t)

	queries := []struct {
		name  string
		query string
		typ   string
	}{
		{"single common CJK term", "提权", "skill"},
		{"single common english term", "ssrf", "skill"},
		{"two terms AND", "linux 提权", "skill"},
		{"three terms AND", "linux 内网 提权", "skill"},
		{"rare exact term", "kerberoasting", "skill"},
		{"vuln common", "rce", "vuln"},
		{"cross-type common", "ssrf", ""},
		{"no match", "zzzznonexistentterm", "skill"},
	}

	fmt.Printf("\n%-30s %12s %12s %8s\n", "QUERY", "COLD", "WARM", "HITS")
	for _, q := range queries {
		// Cold: first execution, includes query planning and any caching.
		cold := time.Now()
		res, err := svc.Search(context.Background(), SearchInput{Query: q.query, Type: q.typ, Limit: 50})
		coldElapsed := time.Since(cold)
		if err != nil {
			t.Fatalf("%s: %v", q.name, err)
		}

		// Warm: median of several runs, to separate per-call cost from the
		// one-time cost of touching the database.
		const runs = 7
		samples := make([]time.Duration, 0, runs)
		for i := 0; i < runs; i++ {
			start := time.Now()
			if _, err := svc.Search(context.Background(), SearchInput{Query: q.query, Type: q.typ, Limit: 50}); err != nil {
				t.Fatal(err)
			}
			samples = append(samples, time.Since(start))
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		fmt.Printf("%-30s %12s %12s %8d\n",
			q.name, coldElapsed.Round(time.Millisecond),
			samples[len(samples)/2].Round(time.Millisecond), res.Total)
	}
	fmt.Println()
}
