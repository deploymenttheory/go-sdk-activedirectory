// Groups reads one group by default; each mutation requires explicit -apply.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adgroups "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/groups"
	"github.com/deploymenttheory/go-sdk-activedirectory/examples/internal/secureauth"
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
	if *server == "" || (*dn == "" && *operation != "create") ||
		(*operation != "read" && !*apply) ||
		(*operation == "create" && (*name == "" || *sam == "")) {
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
	client, err := secureauth.Dial(ctx, server)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	var result adgroups.GroupMutationResult
	switch operation {
	case "read":
		observed, readErr := client.Groups.Group(ctx, identity, ad.ResolveIdentityOptions{})
		if observed.Group != nil {
			fmt.Println(observed.Group.DistinguishedName)
		}
		return readErr
	case "create":
		result, err = client.Groups.CreateGroup(
			ctx,
			adgroups.CreateGroupRequest{
				Parent:         identity,
				Name:           name,
				SAMAccountName: &sam,
				Category:       adgroups.GroupSecurity,
				Scope:          adgroups.GroupGlobal,
			},
		)
	case "describe":
		result, err = client.Groups.UpdateGroup(
			ctx,
			adgroups.UpdateGroupRequest{Identity: identity, Description: &description},
		)
	case "delete":
		result, err = client.Groups.DeleteGroup(
			ctx,
			adgroups.DeleteGroupRequest{Identity: identity},
		)
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf(
		"write-state=%d verified=%t readback=%t\n",
		result.Mutation.State,
		result.Mutation.Verified,
		result.Mutation.ReadbackComplete,
	)
	if result.Group != nil {
		fmt.Println(result.Group.DistinguishedName)
	}
	return err
}
