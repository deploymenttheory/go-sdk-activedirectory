// msaprobe reports what the native managed-account APIs say about one account,
// so the reference cmdlets' behaviour can be compared against the native state
// they are presumed to read.
//
// It answers the open question behind issues #48 and #49: the lab established
// that Test-ADServiceAccount reports eligibility rather than installation, but
// not which native state corresponds. NetQueryServiceAccount returns an
// MSA_INFO_STATE that distinguishes "can install" from "installed"; this probe
// records it alongside NetIsServiceAccount's simpler boolean at each point in
// a fixture's lifecycle.
//
// Read-only by default. It is a diagnostic, not a qualification gate.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type reading struct {
	Account string `json:"account"`
	// IsServiceAccount is NetIsServiceAccount's boolean: whether the name is a
	// managed account at all. Nil when the call did not complete.
	IsServiceAccount *bool   `json:"is_service_account"`
	IsStatus         *uint32 `json:"is_status,omitempty"`
	// State and AccountType come from NetQueryServiceAccount level 1.
	State           *int32   `json:"state"`
	StateName       string   `json:"state_name,omitempty"`
	AccountType     *int32   `json:"account_type"`
	AccountTypeName string   `json:"account_type_name,omitempty"`
	QueryStatus     *uint32  `json:"query_status,omitempty"`
	Errors          []string `json:"errors,omitempty"`
	Unsupported     []string `json:"unsupported,omitempty"`
}

func main() {
	account := flag.String("account", "", "managed account name without a trailing $")
	flag.Parse()
	if *account == "" {
		fmt.Fprintln(os.Stderr, "usage: msaprobe -account <name>")
		os.Exit(2)
	}
	result := probe(*account)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}
