// Command addmsareference assesses a retained dMSA reference bundle offline.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/deploymenttheory/go-sdk-activedirectory/internal/dmsareference"
)

func main() {
	root := flag.String("results", "", "directory containing run.json and captured artifacts")
	flag.Parse()
	if *root == "" {
		fmt.Fprintln(os.Stderr, "-results is required")
		os.Exit(1)
	}
	report, err := dmsareference.Assess(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !report.EvidenceComplete {
		os.Exit(2)
	}
}
