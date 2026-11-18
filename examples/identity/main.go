package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/examples/internal/secureauth"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server DNS name")
	dn := flag.String("dn", "", "object distinguished name")
	partition := flag.String("partition", "", "optional explicit naming context")
	flag.Parse()
	if *server == "" || *dn == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *partition); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, dn, partition string) (err error) {
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
	result, err := client.Directory.ResolveIdentity(
		ctx,
		identity,
		ad.ResolveIdentityOptions{
			Partition:  partition,
			Properties: []string{"objectGUID", "description", "whenChanged"},
		},
	)
	if err != nil {
		return err
	}
	fmt.Println(result.Object.DistinguishedName)
	raw, err := result.Object.Values("objectGUID").Single()
	if err != nil {
		return err
	}
	guid, err := raw.GUID()
	if err != nil {
		return err
	}
	fmt.Println("GUID:", guid.String())

	// The resolved GUID is the stable identifier for this object: a rename or a
	// move changes the DN, and nothing changes the GUID. Writing it down takes
	// the form-prefixed encoding rather than String(), which drops the form and
	// so cannot be parsed back.
	stable, err := ad.IdentityByGUID(guid.String())
	if err != nil {
		return err
	}
	stored, err := stable.MarshalText()
	if err != nil {
		return err
	}
	recovered, err := ad.ParseIdentity(string(stored))
	if err != nil {
		return err
	}
	fmt.Printf("persist as: %s (reads back as form %s)\n", stored, recovered.Form())

	description := result.Object.Values("description")
	fmt.Printf("description state: %d, values: %d\n", description.State, len(description.Values))
	return nil
}
