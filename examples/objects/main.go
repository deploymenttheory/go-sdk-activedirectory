// Objects is read-only unless both an explicit operation and -apply are given.
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
	server := flag.String("server", "", "explicit LDAP server DNS name")
	dn := flag.String("dn", "", "object DN; parent DN for create")
	partition := flag.String("partition", "", "optional naming context")
	operation := flag.String("operation", "read", "read, create, set-description, rename, or delete")
	class := flag.String("class", "container", "schema LDAP display name for create")
	name := flag.String("name", "", "literal new name for create/rename")
	description := flag.String("description", "", "literal value for set-description (empty is a value, not clear)")
	apply := flag.Bool("apply", false, "explicitly execute the selected write")
	recursive := flag.Bool("recursive", false, "explicitly request one potentially partial tree delete")
	flag.Parse()
	if *server == "" || *dn == "" || (*operation != "read" && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *partition, *operation, *class, *name, *description, *recursive); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, partition, operation, class, name, description string, recursive bool) (err error) {
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
	options := ad.ObjectMutationOptions{Partition: partition}
	var result ad.ObjectMutationResult
	switch operation {
	case "read":
		observed, readErr := client.ResolveIdentity(ctx, identity, ad.ResolveIdentityOptions{Partition: partition, Properties: []string{"objectGUID", "uSNChanged"}})
		if readErr != nil {
			return readErr
		}
		fmt.Println(observed.Object.DistinguishedName)
		return nil
	case "create":
		result, err = client.CreateObject(ctx, ad.CreateObjectRequest{Parent: identity, Class: class, Name: name, Options: options})
	case "set-description":
		result, err = client.UpdateObject(ctx, ad.UpdateObjectRequest{Identity: identity, Changes: []ad.AttributeChange{{Attribute: "description", Kind: ad.AttributeSet, Values: []ad.RawValue{ad.NewRawValue([]byte(description))}}}, Options: options})
	case "rename":
		result, err = client.RenameObject(ctx, ad.RenameObjectRequest{Identity: identity, Name: name, Options: options})
	case "delete":
		result, err = client.DeleteObject(ctx, ad.DeleteObjectRequest{Identity: identity, Recursive: recursive, Options: options})
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	fmt.Printf("state=%d readback=%t verified=%t partial-effects-possible=%t\n", result.State, result.ReadbackComplete, result.Verified, result.PartialEffectsPossible)
	if result.After != nil {
		fmt.Println(result.After.DistinguishedName)
	}
	return err // Never repeat or roll back an uncertain/unverified operation.
}
