// Organizational-units reads by default; every write requires -apply.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adorganizationalunits "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/organizational_units"
	"github.com/deploymenttheory/go-sdk-activedirectory/examples/internal/secureauth"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server")
	dn := flag.String("dn", "", "OU DN, or parent DN for create")
	operation := flag.String(
		"operation",
		"read",
		"read, create, set-description, protect, unprotect, delete",
	)
	name := flag.String("name", "", "literal name for create")
	description := flag.String("description", "", "literal description for set-description")
	apply := flag.Bool(
		"apply",
		false,
		"execute the explicitly selected write; protect can also change the parent ACL",
	)
	unprotected := flag.Bool("unprotected", false, "create without accidental-deletion protection")
	recursive := flag.Bool("recursive", false, "explicit potentially partial subtree deletion")
	flag.Parse()
	if *server == "" || *dn == "" || (*operation != "read" && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(
		*server,
		*dn,
		*operation,
		*name,
		*description,
		*unprotected,
		*recursive,
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, operation, name, description string, unprotected, recursive bool) (err error) {
	identity, err := ad.IdentityByDN(dn)
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
	var result any
	switch operation {
	case "read":
		result, err = client.OrganizationalUnits.OrganizationalUnit(
			ctx,
			identity,
			ad.ResolveIdentityOptions{Properties: []string{"ProtectedFromAccidentalDeletion"}},
		)
	case "create":
		protect := !unprotected
		result, err = client.OrganizationalUnits.CreateOrganizationalUnit(
			ctx,
			adorganizationalunits.CreateOrganizationalUnitRequest{
				Parent:                          identity,
				Name:                            name,
				ProtectedFromAccidentalDeletion: &protect,
			},
		)
	case "set-description":
		result, err = client.OrganizationalUnits.UpdateOrganizationalUnit(
			ctx,
			adorganizationalunits.UpdateOrganizationalUnitRequest{
				Identity:   identity,
				Properties: adorganizationalunits.OUProperties{Description: &description},
			},
		)
	case "protect", "unprotect":
		result, err = client.OrganizationalUnits.SetOrganizationalUnitProtection(
			ctx,
			identity,
			operation == "protect",
			ad.ObjectMutationOptions{},
		)
	case "delete":
		result, err = client.OrganizationalUnits.DeleteOrganizationalUnit(
			ctx,
			adorganizationalunits.DeleteOrganizationalUnitRequest{
				Identity:  identity,
				Recursive: recursive,
			},
		)
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf("%+v\n", result) // Inspect outcomes even when an operation failed.
	return err
}
