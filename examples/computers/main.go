// Computers reads by default. Create leaves an account disabled and does not
// join a machine. Every mutation requires an explicit -apply flag.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adcomputers "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/computers"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server")
	dn := flag.String("dn", "", "computer DN; optional parent DN for create")
	operation := flag.String("operation", "read", "read, create, locate or delete")
	name := flag.String(
		"name",
		"",
		"literal computer name for create; SAM name derives with trailing $",
	)
	location := flag.String("location", "", "literal location for locate")
	apply := flag.Bool("apply", false, "execute the selected mutation once")
	flag.Parse()
	if *server == "" || (*dn == "" && *operation != "create") ||
		(*operation != "read" && !*apply) ||
		(*operation == "create" && *name == "") {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *operation, *name, *location); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, operation, name, location string) (err error) {
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
	var result adcomputers.ComputerMutationResult
	switch operation {
	case "read":
		observed, readErr := client.Computers.Computer(ctx, identity, ad.ResolveIdentityOptions{})
		if observed.Computer != nil {
			fmt.Println(observed.Computer.DistinguishedName)
		}
		return readErr
	case "create":
		created, createErr := client.Computers.CreateComputer(
			ctx,
			adcomputers.CreateComputerRequest{Parent: identity, Name: name},
		)
		fmt.Printf(
			"create-state=%d verified=%t complete=%t\n",
			created.Creation.State,
			created.Creation.Verified,
			created.Complete,
		)
		if created.Computer != nil {
			fmt.Println(created.Computer.DistinguishedName)
		}
		return createErr
	case "locate":
		result, err = client.Computers.UpdateComputer(
			ctx,
			adcomputers.UpdateComputerRequest{
				Identity:   identity,
				Properties: adcomputers.ComputerProperties{Location: &location},
			},
		)
	case "delete":
		result, err = client.Computers.DeleteComputer(
			ctx,
			adcomputers.DeleteComputerRequest{Identity: identity},
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
	return err
}
