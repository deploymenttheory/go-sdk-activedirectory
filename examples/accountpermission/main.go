// Accountpermission is read-only unless an explicit operation and -apply are set.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server")
	dn := flag.String("dn", "", "explicit account DN")
	partition := flag.String("partition", "", "optional naming context")
	operation := flag.String("operation", "read", "read, deny, or allow the SELF/Everyone Change-Password permission")
	apply := flag.Bool("apply", false, "execute the explicitly selected DACL write")
	flag.Parse()
	if *server == "" || *dn == "" || (*operation != "read" && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *partition, *operation); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, partition, operation string) (err error) {
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
		result, readErr := client.AccountPasswordChangePermission(ctx, identity, ad.ResolveIdentityOptions{Partition: partition})
		fmt.Printf("%+v\n", result.Permission)
		return readErr
	}
	if operation != "deny" && operation != "allow" {
		return fmt.Errorf("unknown operation %q", operation)
	}
	result, err := client.SetAccountCannotChangePassword(ctx, identity, operation == "deny", ad.ObjectMutationOptions{Partition: partition})
	fmt.Printf("state=%d changed=%t readback=%t verified=%t permission=%+v\n", result.Mutation.State, result.Changed, result.Mutation.ReadbackComplete, result.Mutation.Verified, result.After)
	return err
}
