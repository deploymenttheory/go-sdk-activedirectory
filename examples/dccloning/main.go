// Run on the local domain controller. See docs/dc-cloning.md for qualification
// limits and the distinction between discovery and generation.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/deploymenttheory/go-sdk-activedirectory/dccloning"
)

func main() {
	directory := flag.String("generate-directory", "", "explicit supported directory in which to generate CustomDCCloneAllowList.xml")
	overwrite := flag.Bool("overwrite", false, "replace an existing custom file at the explicit output location")
	flag.Parse()
	if *overwrite && *directory == "" {
		fmt.Fprintln(os.Stderr, "-overwrite requires -generate-directory")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var output any
	var err error
	if *directory == "" {
		output, err = dccloning.Inspect(ctx)
	} else {
		output, err = dccloning.Generate(ctx, dccloning.GenerateOptions{Directory: *directory, Overwrite: *overwrite})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(output); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
