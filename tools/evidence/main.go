// Command evidence writes the verification evidence of Auth-All.
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

	// The scenarios of the v0.3.0 release. Section 9 of the design document
	// names them.
	{"SCN-ADM-001", rootPackage, "TestSCNADM001AViewerCannotListTheUsers"},
	{"SCN-ADM-002", rootPackage, "TestSCNADM002ThePagesCoverEveryUser"},
	{"SCN-ADM-003", rootPackage, "TestSCNADM003AnAdminCreatesAUserWithATemporaryPassword"},
	{"SCN-ADM-004", rootPackage, "TestSCNADM004ThePasswordChangeClearsTheFlag"},
	{"SCN-ADM-005", rootPackage, "TestSCNADM005AnUnknownRoleIsRefused"},
	{"SCN-ADM-006", rootPackage, "TestSCNADM006DisableEndsEverySession"},
	{"SCN-ADM-007", rootPackage, "TestSCNADM007EnableRestoresTheSignIn"},
	{"SCN-ADM-008", rootPackage, "TestSCNADM008AResetEndsEverySession"},
	{"SCN-ADM-009", rootPackage, "TestSCNADM009TheLastAdminKeepsTheRole"},
	{"SCN-ADM-010", rootPackage, "TestSCNADM010TheGuardHoldsUnderConcurrency"},
	{"SCN-ADM-011", rootPackage, "TestSCNADM011AnAdminCannotDisableTheOwnAccount"},
	{"SCN-ADM-012", rootPackage, "TestSCNADM012ACrossSitePostIsRefused"},
	{"SCN-AUD-001", rootPackage, "TestSCNAUD001EveryOperationEmitsOneEvent"},
	{"SCN-AUD-002", rootPackage, "TestSCNAUD002NoEventCarriesASecret"},
	{"SCN-AUD-003", rootPackage, "TestSCNAUD003AHandlerErrorChangesNoResponse"},
	{"SCN-CON-001", rootPackage, "TestSCNCON001TheSecondInstanceRefusesADisabledUser"},
	{"SCN-CON-002", rootPackage, "TestSCNCON002TheCacheTimeStaysInsideTheBound"},
	{"SCN-CON-003", rootPackage, "TestSCNCON003TheCacheEndsInsideTheBound"},
	{"SCN-CON-004", rootPackage, "TestSCNCON004NoPackageKeepsPrincipalsInMemory"},
	{"SCN-CSRF-001", rootPackage, "TestSCNCSRF001ACookiePostFromAnUntrustedOriginIsRefused"},
	{"SCN-CSRF-002", rootPackage, "TestSCNCSRF002TheHostCanTurnTheCheckOff"},
	{"SCN-HTTP-001", rootPackage, "TestSCNHTTP001ConstructionRefusesAnUnusableConfiguration"},
	{"SCN-HTTP-002", rootPackage, "TestSCNHTTP002EveryNewCodeHasAStatusAndAMessage"},
	{"SCN-HTTP-003", rootPackage, "TestSCNHTTP003TheHostWriterShapesEveryError"},
	{"SCN-HTTP-004", rootPackage, "TestSCNHTTP004TheHandlerServesUnderEveryRouter"},
	{"SCN-KEY-001", rootPackage, "TestSCNKEY001EveryKeyHasThePrefixAndIsUnique"},
	{"SCN-KEY-002", rootPackage, "TestSCNKEY002TheCreateResponseCarriesThePlaintextOneTime"},
	{"SCN-KEY-003", rootPackage, "TestSCNKEY003TheStoredRowHoldsOnlyTheDigest"},
	{"SCN-KEY-004", rootPackage, "TestSCNKEY004TheCreateGuardsRefuseAnInvalidKey"},
	{"SCN-KEY-005", rootPackage, "TestSCNKEY005AKeyNeverOutranksTheOwner"},
	{"SCN-KEY-006", rootPackage, "TestSCNKEY006ADemotedOwnerWeakensTheKey"},
	{"SCN-KEY-007", rootPackage, "TestSCNKEY007TheTouchWritesOnceForEachInterval"},
	{"SCN-KEY-008", rootPackage, "TestSCNKEY008AnAdminRevokesAnyKey"},
	{"SCN-KEY-009", rootPackage, "TestSCNKEY009EveryFailedKeyLooksEqual"},
	{"SCN-KEY-010", rootPackage, "TestSCNKEY010AKeyReachesAHostRoute"},
	{"SCN-KEY-011", rootPackage, "TestSCNKEY011AKeyManagesNoKeyAndNoPassword"},
	{"SCN-OPS-001", rootPackage, "TestSCNOPS001BootstrapCreatesOneAdmin"},
	{"SCN-OPS-002", rootPackage, "TestSCNOPS002ParallelBootstrapCreatesOneUser"},
	{"SCN-OPS-003", rootPackage, "TestSCNOPS003AWeakPasswordFailsTheBootstrap"},
	{"SCN-OPS-004", rootPackage, "TestSCNOPS004TheBootstrapUserKeepsThePassword"},
	{"SCN-OPS-005", rootPackage, "TestSCNOPS005TheOperatorMethodsEmitSystemEvents"},
	{"SCN-OPS-006", rootPackage + "/cmd/auth-all", "TestSCNOPS006TheCLICreatesAUserThatSignsIn"},
	{"SCN-PG-001", rootPackage + "/store/postgres", "TestSCNPG001TheContractPassesOverAPool"},
	{"SCN-PG-002", rootPackage + "/store/postgres", "TestSCNPG002ThePoolRefusesAStatementCache"},
	{"SCN-PG-003", rootPackage + "/store/postgres", "TestSCNPG003TheContractPassesThroughATransactionPooler"},
	{"SCN-RL-001", rootPackage, "TestSCNRL001TheSixthSignInForOneEmailIsRefused"},
	{"SCN-RL-002", rootPackage + "/ratelimit/storelimit", "TestSCNRL002ARuleSetRefusesWhenEitherRuleIsOver"},
	{"SCN-RL-003", rootPackage + "/ratelimit/storelimit", "TestSCNRL003ParallelAttemptsAllowExactlyTheLimit"},
	{"SCN-RL-004", rootPackage + "/ratelimit/storelimit", "TestSCNRL004TheAddressKeyCountsPerBlock"},
	{"SCN-RL-005", rootPackage + "/ratelimit/storelimit", "TestSCNRL005TheTableHoldsNoAddress"},
	{"SCN-RL-006", rootPackage, "TestSCNRL006AStoreFailureRefusesTheRequest"},
	{"SCN-RL-007", rootPackage + "/ratelimit/storelimit", "TestSCNRL007CleanupRemovesOnlyEndedWindows"},
	{"SCN-RL-008", rootPackage, "TestSCNRL008AV1LimiterKeepsTheV1Behavior"},
	{"SCN-ROLE-001", rootPackage, "TestSCNROLE001AnInvalidHierarchyFailsConstruction"},
	{"SCN-ROLE-002", rootPackage, "TestSCNROLE002ANewUserGetsTheDefaultRole"},
	{"SCN-ROLE-003", rootPackage, "TestSCNROLE003ALowerRoleIsRefused"},
	{"SCN-ROLE-004", rootPackage, "TestSCNROLE004AnAnonymousRequestIsRefused"},
	{"SCN-ROLE-005", rootPackage, "TestSCNROLE005AnUnknownRoleRanksBelowEveryRole"},
	{"SCN-ROLE-006", rootPackage, "TestSCNROLE006TheRoleHelpersAnswerEveryPair"},
	{"SCN-SCH-001", rootPackage + "/schema", "TestSCNSCH001ExportMatchesTheGoldenFiles"},
	{"SCN-SCH-002", rootPackage + "/migrations", "TestSCNSCH002TheGooseExportAppliesAndRollsBack"},
	{"SCN-SCH-003", rootPackage + "/cmd/auth-all", "TestSCNSCH003TheCLIExportsTheMigrationFiles"},
	{"SCN-SCH-004", rootPackage + "/store/postgres", "TestSCNSCH004TheContractPassesWithAPrefixAndUUIDKeys"},
	{"SCN-SCH-005", rootPackage + "/schema", "TestSCNSCH005AnInvalidPrefixFailsConstruction"},
	{"SCN-SCH-006", rootPackage, "TestSCNSCH006TheInputAndOutputRulesHold"},
	{"SCN-SCH-007", rootPackage, "TestSCNSCH007ATypeMismatchReportsAnError"},
	{"SCN-SCH-008", rootPackage + "/migrations", "TestSCNSCH008TheCatalogCheckReadsTheAppliedExport"},
	{"SCN-SES-001", rootPackage, "TestSCNSES001RevokeOtherSessionsKeepsTheCurrentOne"},
	{"SCN-SES-002", rootPackage, "TestSCNSES002TheRevokeAllRouteKeepsTheV1Contract"},

	// The scenarios of the v0.4.0 organizations release.
	{"SCN-ORG-001", rootPackage, "TestSCNORG001TheCreatorHoldsTheOwnerRole"},
	{"SCN-ORG-002", rootPackage, "TestSCNORG002TheSlugRulesHold"},
	{"SCN-ORG-003", rootPackage, "TestSCNORG003TheDeletionRunsTheBeforeHook"},
	{"SCN-ORG-003", rootPackage, "TestSCNORG003TheDeletionRemovesTheOrganizationKeys"},
	{"SCN-ORG-004", rootPackage + "/store/postgres", "TestStorageContract/SCNORG004ThePagesCoverEveryOrganization"},
	{"SCN-ORG-004", rootPackage + "/store/sqlite", "TestStorageContract/SCNORG004ThePagesCoverEveryOrganization"},
	{"SCN-ORG-005", rootPackage, "TestSCNORG005ThePersonalOrganizationIsAnOption"},
	{"SCN-ORG-006", rootPackage, "TestSCNORG006TheUpdateWritesEveryField"},
	{"SCN-MEM-001", rootPackage + "/store/postgres", "TestStorageContract/SCNMEM001OneUserHoldsThreeMemberships"},
	{"SCN-MEM-001", rootPackage + "/store/sqlite", "TestStorageContract/SCNMEM001OneUserHoldsThreeMemberships"},
	{"SCN-MEM-002", rootPackage + "/store/postgres", "TestStorageContract/SCNMEM002ASecondMembershipInOneOrganizationFails"},
	{"SCN-MEM-002", rootPackage + "/store/sqlite", "TestStorageContract/SCNMEM002ASecondMembershipInOneOrganizationFails"},
	{"SCN-MEM-003", rootPackage, "TestSCNMEM003TheRoleChangeAcceptsOnlyAKnownRole"},
	{"SCN-MEM-004", rootPackage, "TestSCNMEM004TheRemovalEndsTheActiveOrganization"},
	{"SCN-MEM-005", rootPackage, "TestSCNMEM005TheLastOwnerKeepsTheRole"},
	{"SCN-MEM-006", rootPackage, "TestSCNMEM006TheOwnerGuardHoldsUnderConcurrency"},
	{"SCN-MEM-007", rootPackage, "TestSCNMEM007AnAdminCannotGrantTheOwnerRole"},
	{"SCN-MEM-008", rootPackage, "TestSCNMEM008SuspendStopsEveryPermission"},
	{"SCN-MEM-009", rootPackage, "TestSCNMEM009ThePagesCoverEveryMember"},
	{"SCN-MEM-010", rootPackage, "TestSCNMEM010TheMemberLimitCountsThePendingInvitations"},
	{"SCN-INV-001", rootPackage, "TestSCNINV001TheTokenAppearsOneTime"},
	{"SCN-INV-002", rootPackage, "TestSCNINV002AnInvitationNeverNamesAHigherRole"},
	{"SCN-INV-003", rootPackage, "TestSCNINV003OnlyTheNamedAddressAccepts"},
	{"SCN-INV-004", rootPackage, "TestSCNINV004TheInvalidCasesLookEqual"},
	{"SCN-INV-005", rootPackage + "/store/postgres", "TestStorageContract/SCNINV005TenParallelAcceptancesSpendOneInvitation"},
	{"SCN-INV-005", rootPackage + "/store/sqlite", "TestStorageContract/SCNINV005TenParallelAcceptancesSpendOneInvitation"},
	{"SCN-INV-006", rootPackage, "TestSCNINV006AMemberNeedsNoInvitation"},
	{"SCN-INV-007", rootPackage, "TestSCNINV007TheInvitationEmitsTheIntent"},
	{"SCN-INV-008", rootPackage, "TestSCNINV008TheExpiryIsSevenDaysAndConfigurable"},
	{"SCN-PRM-001", rootPackage + "/plugins/organizations/permission", "TestSCNPRM001TheWildcardCoversItsSegment"},
	{"SCN-PRM-002", rootPackage + "/plugins/organizations/permission", "TestSCNPRM002TheGrammarRefusesAPattern"},
	{"SCN-PRM-003", rootPackage, "TestSCNPRM003TheWriteRouteNeedsTheWritePermission"},
	{"SCN-PRM-004", rootPackage, "TestSCNPRM004AnUnknownPermissionIsDenied"},
	{"SCN-PRM-005", rootPackage, "TestSCNPRM005NoActiveOrganizationRefuses"},
	{"SCN-PRM-006", rootPackage + "/plugins/organizations", "TestSCNPRM006RequirePanicsForAnUnheldPermission"},
	{"SCN-PRM-007", rootPackage, "TestSCNPRM007ACustomRoleNeverEscalates"},
	{"SCN-PRM-008", rootPackage, "TestSCNPRM008CanAnswersEveryPair"},
	{"SCN-CTX-001", rootPackage, "TestSCNCTX001TheSwitchChangesThePermissions"},
	{"SCN-CTX-002", rootPackage, "TestSCNCTX002ASwitchNeedsAMembership"},
	{"SCN-CTX-003", rootPackage, "TestSCNCTX003TheCredentialReadCostsOneRoundTrip"},
	{"SCN-CTX-004", rootPackage, "TestSCNCTX004ARemovalTakesEffectOnEveryInstance"},
	{"SCN-CTX-005", rootPackage, "TestSCNCTX005ARequestValueNeverSetsTheOrganization"},
	{"SCN-TEAM-001", rootPackage, "TestSCNTEAM001ThePermissionsAreTheUnion"},
	{"SCN-TEAM-002", rootPackage, "TestSCNTEAM002ATeamNeedsAnOrganizationMembership"},
	{"SCN-TEAM-003", rootPackage, "TestSCNTEAM003TheTeamDeletionKeepsTheMemberships"},
	{"SCN-INT-001", rootPackage, "TestSCNINT001AnOrganizationKeyFollowsItsOwner"},
	{"SCN-INT-002", rootPackage, "TestSCNINT002TheGlobalRoleKeepsItsBehavior"},
	{"SCN-INT-003", rootPackage, "TestSCNINT003AnApplicationAdministratorManagesEveryOrganization"},
	{"SCN-INT-004", rootPackage, "TestSCNINT004TheObjectCheckerIsOptional"},
	{"SCN-INT-005", rootPackage, "TestSCNINT005EveryChangeEmitsAnEvent"},
}

// The huma scenarios SCN-HTTP-005 and SCN-HTTP-006 live in the humaauth
// module. The verification command runs that module in the step test-huma, and
// the check list below records the result.

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
	out := flag.String("out", "artifacts/verification.md", "the evidence file")
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
	b.WriteString("# Auth-All verification evidence\n\n")
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
		if strings.HasSuffix(strings.TrimSpace(line), "-verification.md") {
			continue
		}
		return "modified"
	}
	return "clean, apart from this generated file"
}
