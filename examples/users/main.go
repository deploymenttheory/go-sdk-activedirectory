// Users reads by default. Each mutation requires -apply; create leaves the user
// disabled. Passwords are never accepted as command-line arguments.
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
	dn := flag.String("dn", "", "user DN, or parent DN for create")
	operation := flag.String("operation", "read", "read, create, describe or delete")
	name := flag.String("name", "", "literal user name for create")
	sam := flag.String("sam", "", "explicit SAM account name for create")
	description := flag.String("description", "", "literal description for describe")
	apply := flag.Bool("apply", false, "execute the selected mutation once")
	flag.Parse()
	if *server == "" || *dn == "" || (*operation != "read" && !*apply) || (*operation == "create" && (*name == "" || *sam == "")) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *operation, *name, *sam, *description); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, operation, name, sam, description string) (err error) {
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
	var result ad.UserMutationResult
	switch operation {
	case "read":
		observed, readErr := client.User(ctx, identity, ad.ResolveIdentityOptions{})
		if observed.User != nil {
			fmt.Println(observed.User.DistinguishedName)
		}
		return readErr
	case "create":
		created, createErr := client.CreateUser(ctx, ad.CreateUserRequest{Parent: identity, Name: name, Properties: ad.UserProperties{SAMAccountName: &sam}})
		fmt.Printf("create-state=%d verified=%t complete=%t\n", created.Creation.State, created.Creation.Verified, created.Complete)
		if created.User != nil {
			fmt.Println(created.User.DistinguishedName)
		}
		return createErr
	case "describe":
		result, err = client.UpdateUser(ctx, ad.UpdateUserRequest{Identity: identity, Properties: ad.UserProperties{Description: &description}})
	case "delete":
		result, err = client.DeleteUser(ctx, ad.DeleteUserRequest{Identity: identity})
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf("write-state=%d verified=%t readback=%t\n", result.Mutation.State, result.Mutation.Verified, result.Mutation.ReadbackComplete)
	if result.User != nil {
		fmt.Println(result.User.DistinguishedName)
	}
	return err
}
