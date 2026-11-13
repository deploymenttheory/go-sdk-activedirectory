package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	name := flag.String("name", "A*(literal)", "literal cn value (wildcards are escaped)")
	server := flag.String("server", "", "optional explicit DC FQDN; empty only prints the filter")
	base := flag.String("base", "", "explicit search base DN when -server is supplied")
	flag.Parse()
	filter := ad.FilterAnd(ad.FilterPresent("objectClass"), ad.FilterEqual("cn", ad.FilterText(*name)))
	encoded, err := filter.LDAP()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(encoded)
	if *server == "" {
		return
	}
	if *base == "" {
		log.Fatal("-base is required with -server")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: *server}})
	if err != nil {
		log.Fatal(err)
	}
	result, searchErr := c.Search(ctx, ad.SearchOptions{Base: *base, Scope: ad.ScopeSubtree, TypedFilter: filter, Properties: []string{"objectGUID", "cn"}})
	closeErr := c.Close()
	for _, object := range result.Objects {
		fmt.Println(object.DistinguishedName)
	}
	if searchErr != nil {
		log.Fatal(searchErr)
	}
	if closeErr != nil {
		log.Fatal(closeErr)
	}
}
