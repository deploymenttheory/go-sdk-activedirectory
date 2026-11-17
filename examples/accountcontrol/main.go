// Accountcontrol reads by default. Writes require an explicit -operation -apply.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adaccounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/accounts"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server")
	dn := flag.String("dn", "", "explicit account distinguished name")
	operation := flag.String("operation", "read", "read, enable, disable or unlock")
	apply := flag.Bool("apply", false, "execute the selected mutation once")
	flag.Parse()
	if *server == "" || *dn == "" || (*operation != "read" && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *operation); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, operation string) (err error) {
	identity, err := ad.IdentityByDN(dn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	if operation == "read" {
		result, readErr := client.Accounts.AccountControl(
			ctx,
			identity,
			ad.ResolveIdentityOptions{},
		)
		if result.Account != nil {
			fmt.Println(result.Account.DistinguishedName)
			if result.Account.Enabled != nil {
				fmt.Println("enabled:", *result.Account.Enabled)
			}
			if result.Account.LockedOut != nil {
				fmt.Println("locked:", *result.Account.LockedOut)
			}
		}
		return readErr
	}
	var result adaccounts.AccountControlMutationResult
	switch operation {
	case "enable":
		result, err = client.Accounts.EnableAccount(ctx, identity, ad.ObjectMutationOptions{})
	case "disable":
		result, err = client.Accounts.DisableAccount(ctx, identity, ad.ObjectMutationOptions{})
	case "unlock":
		result, err = client.Accounts.UnlockAccount(ctx, identity, ad.ObjectMutationOptions{})
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf(
		"write-state=%d verified=%t readback=%t\n",
		result.Mutation.State,
		result.Mutation.Verified,
		result.Mutation.ReadbackComplete,
	)
	return err
}
