// Command coverage reports the statement coverage of one package set.
//
// NFR-05 asks for 85 percent of statements in every package that the v1.1
// release adds. The command reads a coverage profile and fails when one named
// package is below the minimum.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// block is the coverage of one statement block.
type block struct {
	statements int
	count      int
}

type packageList []string

// String implements flag.Value.
func (p *packageList) String() string { return strings.Join(*p, ", ") }

// Set implements flag.Value.
func (p *packageList) Set(value string) error {
	*p = append(*p, value)
	return nil
}

func main() {
	var packages packageList
	profile := flag.String("profile", "coverage.out", "the coverage profile")
	minimum := flag.Float64("minimum", 85, "the lowest accepted percentage")
	flag.Var(&packages, "package", "a package that must reach the minimum")
	flag.Parse()

	raw, err := os.ReadFile(*profile)
	if err != nil {
		fail(err)
	}
	// One profile can hold the same block several times, because every test
	// binary writes its own result. The highest count wins.
	best := map[string]block{}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		statements, err := strconv.Atoi(fields[1])
		if err != nil {
			fail(err)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			fail(err)
		}
		if have, ok := best[fields[0]]; !ok || count > have.count {
			best[fields[0]] = block{statements: statements, count: count}
		}
	}

	total := map[string]int{}
	covered := map[string]int{}
	for name, b := range best {
		path := name
		if index := strings.Index(path, ":"); index >= 0 {
			path = path[:index]
		}
		path = path[:strings.LastIndex(path, "/")]
		total[path] += b.statements
		if b.count > 0 {
			covered[path] += b.statements
		}
	}

	sort.Strings(packages)
	failed := false
	for _, name := range packages {
		if total[name] == 0 {
			fmt.Printf("%s: the profile holds no statement\n", name)
			failed = true
			continue
		}
		percent := 100 * float64(covered[name]) / float64(total[name])
		state := "ok"
		if percent < *minimum {
			state = "below the minimum"
			failed = true
		}
		fmt.Printf("%-55s %5.1f%% %s\n", name, percent, state)
	}
	if failed {
		fmt.Fprintf(os.Stderr, "coverage: one package is below %.0f percent\n", *minimum)
		os.Exit(1)
	}
}

// fail stops the command with one error.
func fail(err error) {
	fmt.Fprintln(os.Stderr, "coverage: "+err.Error())
	os.Exit(1)
}
