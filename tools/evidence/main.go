// Command evidence writes the v1 verification evidence of Auth-All.
//
// It re-runs the acceptance suite, maps every normative scenario id of the
// specification to the test that proves it, and records the result together
// with the checks that the verification command already passed.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// scenario binds one normative scenario id to the test that proves it.
type scenario struct {
	ID      string
	Package string
	Test    string
}

const rootPackage = "github.com/alternayte/auth-all"

var scenarios = []scenario{
	{"AUTH-001", rootPackage, "TestAUTH001SignUp"},
	{"AUTH-002", rootPackage, "TestAUTH002DuplicateSignUp"},
	{"AUTH-003", rootPackage, "TestAUTH003SignIn"},
	{"AUTH-004", rootPackage, "TestAUTH004InvalidCredentials"},
	{"AUTH-005", rootPackage, "TestAUTH005SignOut"},
	{"AUTH-006", rootPackage, "TestAUTH006SessionLookup"},
	{"AUTH-007", rootPackage, "TestAUTH007And008EmailVerification"},
	{"AUTH-008", rootPackage, "TestAUTH007And008EmailVerification"},
	{"AUTH-009", rootPackage, "TestAUTH009And010PasswordReset"},
	{"AUTH-010", rootPackage, "TestAUTH009And010PasswordReset"},
	{"AUTH-011", rootPackage, "TestAUTH011MagicLinkRequest"},
	{"AUTH-012", rootPackage, "TestAUTH012MagicLinkAuthentication"},
	{"AUTH-013", rootPackage, "TestAUTH013MagicLinkReplay"},
	{"AUTH-014", rootPackage, "TestAUTH014GitHubOAuth"},
	{"AUTH-015", rootPackage, "TestAUTH015GoogleOAuth"},
	{"AUTH-016", rootPackage, "TestAUTH016InvalidOAuthState"},
	{"AUTH-017", rootPackage, "TestAUTH017ExplicitAccountLinking"},
	{"AUTH-018", rootPackage, "TestAUTH018UnsafeAutoLinkPrevention"},
	{"AUTH-019", rootPackage, "TestAUTH019AccountUnlink"},
	{"PLUG-001", rootPackage, "TestPLUG001Route"},
	{"PLUG-002", rootPackage, "TestPLUG002Schema"},
	{"PLUG-003", rootPackage, "TestPLUG003Hook"},
	{"PLUG-004", rootPackage, "TestPLUG004OpenAPI"},
	{"PLUG-005", rootPackage, "TestPLUG005GeneratedClientPluginOperation"},
	{"PLUG-006", rootPackage, "TestPLUG006MagicLinkUsesPublicAPIsOnly"},
	{"DB-001", rootPackage + "/store/postgres", "TestStorageContract"},
	{"DB-002", rootPackage + "/store/sqlite", "TestStorageContract"},
	{"MIG-001", rootPackage, "TestMIG001FreshMigration"},
	{"MIG-002", rootPackage, "TestMIG002DeterministicSQL"},
	{"MIG-003", rootPackage, "TestMIG003NoStartupAutoMigrate"},
	{"API-001", rootPackage, "TestAPI001OpenAPICompleteness"},
	{"API-002", rootPackage, "TestAPI002GeneratedArtifactFreshness"},
	{"SEC-001", rootPackage, "TestSEC001SecretsAbsentFromErrors"},
	{"SEC-002", rootPackage, "TestSEC002SessionTokenStorage"},
	{"SEC-003", rootPackage, "TestSEC003OneTimeTokenStorage"},
	{"SEC-004", rootPackage, "TestSEC004TrustedOriginEnforcement"},
	{"C-001", rootPackage, "TestC001ConcurrentSignUp"},
	{"C-001", rootPackage + "/store/postgres", "TestStorageContract/ConcurrentSignUpSameEmail"},
	{"C-001", rootPackage + "/store/sqlite", "TestStorageContract/ConcurrentSignUpSameEmail"},
	{"C-002", rootPackage, "TestC002ConcurrentTokenConsume"},
	{"C-002", rootPackage + "/store/postgres", "TestStorageContract/ConcurrentTokenConsume"},
	{"C-002", rootPackage + "/store/sqlite", "TestStorageContract/ConcurrentTokenConsume"},
	{"C-003", rootPackage, "TestProviderIdentityBelongsToOneUser"},
	{"C-003", rootPackage + "/store/postgres", "TestStorageContract/ConcurrentAccountLink"},
	{"C-003", rootPackage + "/store/sqlite", "TestStorageContract/ConcurrentAccountLink"},
	{"C-004", rootPackage, "TestC004SessionRevocationUnderLoad"},
	{"C-004", rootPackage + "/store/postgres", "TestStorageContract/SessionRevocationIsFinal"},
	{"C-004", rootPackage + "/store/sqlite", "TestStorageContract/SessionRevocationIsFinal"},
}

type testEvent struct {
	Action  string `json:"Action"`
	Package string `json:"Package"`
	Test    string `json:"Test"`
}

type checkResult struct {
	Name    string
	Command string
	Status  string
}

func main() {
	checksPath := flag.String("checks", "artifacts/checks.tsv", "the recorded check results")
	out := flag.String("out", "artifacts/v1-verification.md", "the evidence file")
	flag.Parse()

	results, skipped, err := runTests()
	if err != nil {
		fmt.Fprintln(os.Stderr, "evidence: "+err.Error())
		os.Exit(1)
	}
	checks, err := readChecks(*checksPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "evidence: "+err.Error())
		os.Exit(1)
	}
	report, blocking := render(results, skipped, checks)
	if err := os.WriteFile(*out, []byte(report), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "evidence: "+err.Error())
		os.Exit(1)
	}
	if blocking > 0 {
		fmt.Fprintf(os.Stderr, "evidence: %d blocking defects remain\n", blocking)
		os.Exit(1)
	}
}

// runTests runs the complete suite and returns the outcome of every test.
func runTests() (map[string]string, []string, error) {
	cmd := exec.Command("go", "test", "-json", "-count=1", "./...")
	cmd.Env = os.Environ()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	results := map[string]string{}
	var skipped []string
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for scanner.Scan() {
		var ev testEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		if ev.Test == "" {
			continue
		}
		switch ev.Action {
		case "pass", "fail":
			results[ev.Package+"|"+ev.Test] = strings.ToUpper(ev.Action)
		case "skip":
			results[ev.Package+"|"+ev.Test] = "SKIP"
			skipped = append(skipped, ev.Package+" "+ev.Test)
		}
	}
	if err := cmd.Wait(); err != nil {
		return results, skipped, fmt.Errorf("the acceptance suite failed: %w", err)
	}
	return results, skipped, nil
}

func readChecks(path string) ([]checkResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the recorded checks: %w. Run: just verify", err)
	}
	var out []checkResult
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}
		out = append(out, checkResult{Name: parts[0], Command: parts[1], Status: parts[2]})
	}
	return out, nil
}

// row is one line of the scenario ledger.
type row struct {
	id       string
	status   string
	evidence []string
}

func render(results map[string]string, skipped []string, checks []checkResult) (string, int) {
	byID := map[string]*row{}
	var order []string
	for _, sc := range scenarios {
		r, ok := byID[sc.ID]
		if !ok {
			r = &row{id: sc.ID, status: "PASS"}
			byID[sc.ID] = r
			order = append(order, sc.ID)
		}
		status := results[sc.Package+"|"+sc.Test]
		if status == "" {
			status = "MISSING"
		}
		if status != "PASS" {
			r.status = status
		}
		r.evidence = append(r.evidence, shortPackage(sc.Package)+" "+sc.Test)
	}
	// CON-001 is proven by the race detector recipe of the verification run.
	raceStatus := "MISSING"
	for _, c := range checks {
		if c.Name == "race detector" {
			raceStatus = c.Status
		}
	}
	byID["CON-001"] = &row{id: "CON-001", status: raceStatus, evidence: []string{"just test-race (go test -race ./...)"}}
	order = append(order, "CON-001")

	passed := 0
	blocking := 0
	for _, id := range order {
		if byID[id].status == "PASS" {
			passed++
			continue
		}
		blocking++
	}
	for _, c := range checks {
		if c.Status != "PASS" {
			blocking++
		}
	}
	if len(skipped) > 0 {
		blocking += len(skipped)
	}

	var b strings.Builder
	b.WriteString("# Auth-All v1 verification evidence\n\n")
	b.WriteString("This file is generated by `just verify`. Do not edit it by hand.\n\n")
	fmt.Fprintf(&b, "- Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Commit SHA: %s\n", commandOutput("git", "rev-parse", "HEAD"))
	fmt.Fprintf(&b, "- Working tree: %s\n", workingTreeState())
	b.WriteString("- Scope: the values below describe the commit named above. " +
		"This file is committed on top of that commit, because it records its own run.\n")
	fmt.Fprintf(&b, "- Go version: %s\n", runtime.Version())
	fmt.Fprintf(&b, "- Node version: %s\n", commandOutput("node", "--version"))
	fmt.Fprintf(&b, "- TypeScript version: %s\n", commandOutput("npx", "--no-install", "tsc", "--version"))
	fmt.Fprintf(&b, "- PostgreSQL adapter: %s\n", scenarioStatus(byID, "DB-001"))
	fmt.Fprintf(&b, "- SQLite adapter: %s\n", scenarioStatus(byID, "DB-002"))
	fmt.Fprintf(&b, "- Race detector: %s\n", raceStatus)
	fmt.Fprintf(&b, "- Generated-file freshness: %s\n", checkStatus(checks, "generated artifact freshness"))
	fmt.Fprintf(&b, "- OpenAPI freshness: %s\n", checkStatus(checks, "OpenAPI freshness"))
	fmt.Fprintf(&b, "- TypeScript client freshness: %s\n", checkStatus(checks, "TypeScript client freshness"))
	fmt.Fprintf(&b, "- Acceptance scenarios: %d of %d PASS\n", passed, len(order))
	fmt.Fprintf(&b, "- Required skipped tests: %d\n", len(skipped))
	fmt.Fprintf(&b, "- `just verify` result: %s\n", verifyResult(blocking))
	fmt.Fprintf(&b, "- Known blocking defects: %d\n\n", blocking)

	b.WriteString("## Acceptance scenario ledger\n\n")
	b.WriteString("| ID | Status | Evidence |\n| --- | --- | --- |\n")
	sort.Strings(order)
	for _, id := range order {
		r := byID[id]
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.id, r.status, strings.Join(r.evidence, "<br>"))
	}

	b.WriteString("\n## Verification checks\n\n")
	b.WriteString("| Check | Status | Command |\n| --- | --- | --- |\n")
	for _, c := range checks {
		fmt.Fprintf(&b, "| %s | %s | `%s` |\n", c.Name, c.Status, c.Command)
	}
	if len(skipped) > 0 {
		b.WriteString("\n## Skipped tests\n\n")
		for _, s := range skipped {
			fmt.Fprintf(&b, "- %s\n", s)
		}
	}
	b.WriteString("\n## How to reproduce\n\n")
	b.WriteString("```bash\njust verify\n```\n")
	return b.String(), blocking
}

func scenarioStatus(byID map[string]*row, id string) string {
	if r, ok := byID[id]; ok {
		return r.status
	}
	return "MISSING"
}

func checkStatus(checks []checkResult, name string) string {
	for _, c := range checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "MISSING"
}

func verifyResult(blocking int) string {
	if blocking == 0 {
		return "PASS (exit code 0)"
	}
	return "FAIL"
}

func shortPackage(pkg string) string {
	if pkg == rootPackage {
		return "."
	}
	return strings.TrimPrefix(pkg, rootPackage+"/")
}

func commandOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// workingTreeState reports the state of the tree that produced the evidence.
// The evidence file itself is excluded, because the run rewrites it.
func workingTreeState() string {
	out := commandOutput("git", "status", "--porcelain")
	if out == "" {
		return "clean"
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasSuffix(strings.TrimSpace(line), "artifacts/v1-verification.md") {
			continue
		}
		return "modified"
	}
	return "clean, apart from this generated file"
}
