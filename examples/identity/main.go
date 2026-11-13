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
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	result, err := client.ResolveIdentity(ctx, identity, ad.ResolveIdentityOptions{Partition: partition, Properties: []string{"objectGUID", "description", "whenChanged"}})
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
	description := result.Object.Values("description")
	fmt.Printf("description state: %d, values: %d\n", description.State, len(description.Values))
	return nil
}
