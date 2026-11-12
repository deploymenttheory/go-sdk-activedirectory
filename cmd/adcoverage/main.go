// Command adcoverage checks the operation contract and its generated report offline.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-sdk-activedirectory/internal/coverage"
)

func main() {
	root := flag.String("root", ".", "repository root")
	write := flag.Bool("write", false, "regenerate the coverage report after validation")
	flag.Parse()
	if err := run(*root, *write); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(root string, write bool) error {
	r, i, err := coverage.Load(root)
	if err != nil {
		return err
	}
	if err := coverage.Validate(root, r, i); err != nil {
		return err
	}
	report := coverage.Report(r, i)
	path := filepath.Join(root, "docs", "coverage.md")
	if write {
		if err := os.WriteFile(path, report, 0o644); err != nil {
			return err
		}
	} else {
		existing, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(bytes.ReplaceAll(existing, []byte("\r\n"), []byte("\n")), report) {
			return fmt.Errorf("coverage report is stale; run go run ./cmd/adcoverage -write")
		}
	}
	fmt.Printf("Coverage contract valid: %d cmdlets\n", len(i.Operations))
	return nil
}
