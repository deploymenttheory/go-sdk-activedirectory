// Groups reads one group by default; each mutation requires explicit -apply.
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
	dn := flag.String("dn", "", "group DN; optional parent DN for create")
	operation := flag.String("operation", "read", "read, create, describe or delete")
	name := flag.String("name", "", "literal group name for create")
	sam := flag.String("sam", "", "explicit SAM account name for create")
	description := flag.String("description", "", "literal description for describe")
	apply := flag.Bool("apply", false, "execute the selected mutation once")
	flag.Parse()
	if *server == "" || (*dn == "" && *operation != "create") || (*operation != "read" && !*apply) || (*operation == "create" && (*name == "" || *sam == "")) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *operation, *name, *sam, *description); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, operation, name, sam, description string) (err error) {
	var identity ad.Identity
	if dn != "" {
		identity, err = ad.IdentityByDN(dn)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	var result ad.GroupMutationResult
	switch operation {
	case "read":
		observed, readErr := client.Group(ctx, identity, ad.ResolveIdentityOptions{})
		if observed.Group != nil {
			fmt.Println(observed.Group.DistinguishedName)
		}
		return readErr
	case "create":
		result, err = client.CreateGroup(ctx, ad.CreateGroupRequest{Parent: identity, Name: name, SAMAccountName: &sam, Category: ad.GroupSecurity, Scope: ad.GroupGlobal})
	case "describe":
		result, err = client.UpdateGroup(ctx, ad.UpdateGroupRequest{Identity: identity, Description: &description})
	case "delete":
		result, err = client.DeleteGroup(ctx, ad.DeleteGroupRequest{Identity: identity})
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf("write-state=%d verified=%t readback=%t\n", result.Mutation.State, result.Mutation.Verified, result.Mutation.ReadbackComplete)
	if result.Group != nil {
		fmt.Println(result.Group.DistinguishedName)
	}
	return err
}
