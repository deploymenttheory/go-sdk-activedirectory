// This example performs reads only and uses the current authenticated identity.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	admemberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
	"github.com/deploymenttheory/go-sdk-activedirectory/examples/internal/secureauth"
)

func main() {
	server := flag.String("server", "", "explicit full domain LDAP server")
	rodc := flag.String("rodc-dn", "", "explicit RODC computer distinguished name")
	operation := flag.String(
		"operation",
		"allowed",
		"allowed, denied, authenticated, revealed, resultant",
	)
	account := flag.String("account-dn", "", "explicit account DN for resultant policy")
	flag.Parse()
	if *server == "" || *rodc == "" || (*operation == "resultant" && *account == "") {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *rodc, *operation, *account); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, rodcDN, operation, accountDN string) (err error) {
	rodc, err := ad.IdentityByDN(rodcDN)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := secureauth.Dial(ctx, server)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	if operation == "resultant" {
		account, err := ad.IdentityByDN(accountDN)
		if err != nil {
			return err
		}
		result, err := client.Memberships.AccountResultantPasswordReplicationPolicy(
			ctx,
			rodc,
			account,
			admemberships.RODCPasswordReplicationOptions{},
		)
		if result.Policy != nil {
			fmt.Printf(
				"policy=%d known=%t complete=%t\n",
				*result.Policy,
				result.Policy.Known(),
				result.Complete,
			)
		}
		return err
	}
	var result admemberships.RODCPasswordReplicationResult
	switch operation {
	case "allowed":
		result, err = client.Memberships.RODCPasswordReplicationPolicy(
			ctx,
			rodc,
			admemberships.RODCPasswordAllowed,
			admemberships.RODCPasswordReplicationOptions{},
		)
	case "denied":
		result, err = client.Memberships.RODCPasswordReplicationPolicy(
			ctx,
			rodc,
			admemberships.RODCPasswordDenied,
			admemberships.RODCPasswordReplicationOptions{},
		)
	case "authenticated":
		result, err = client.Memberships.RODCPasswordReplicationPolicyUsage(
			ctx,
			rodc,
			admemberships.RODCPasswordAuthenticated,
			admemberships.RODCPasswordReplicationOptions{},
		)
	case "revealed":
		result, err = client.Memberships.RODCPasswordReplicationPolicyUsage(
			ctx,
			rodc,
			admemberships.RODCPasswordRevealed,
			admemberships.RODCPasswordReplicationOptions{},
		)
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf(
		"attribute=%s accounts=%d entries=%d complete=%t returned=%t\n",
		result.Attribute,
		len(result.Principals),
		len(result.Entries),
		result.Complete,
		result.AttributeReturned,
	)
	for _, principal := range result.Principals {
		fmt.Println(principal.Object.DistinguishedName)
	}
	return err
}
