// Command adreference refreshes the pinned reference from local Microsoft source files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/deploymenttheory/go-sdk-activedirectory/internal/coverage"
)

func main() {
	source := flag.String("source", "", "directory containing the official cmdlet Markdown files")
	commit := flag.String("commit", "", "full Microsoft documentation commit SHA")
	root := flag.String("root", ".", "repository root containing the approved reference")
	out := flag.String("out", "coverage/reference.json", "snapshot output file")
	flag.Parse()
	if err := run(*source, *commit, *root, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(source, commit, root, out string) error {
	if source == "" || commit == "" {
		return fmt.Errorf("-source and -commit are required")
	}
	old, _, err := coverage.Load(root)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(old.Commands))
	for _, c := range old.Commands {
		names = append(names, c.Name)
	}
	r, err := coverage.ImportReference(source, commit, names)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, append(data, '\n'), 0o644)
}
