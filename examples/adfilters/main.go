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
	surname := flag.String("surname", "O'Neil", "literal surname value")
	server := flag.String("server", "", "optional DC FQDN; empty only prints LDAP")
	base := flag.String("base", "", "explicit search base required with -server")
	flag.Parse()
	filter, err := ad.ParseADFilter(`Enabled -eq $true -and Surname -eq $surname`, ad.ADFilterOptions{Profile: ad.ADFilterUser, Variables: map[string]any{"surname": *surname}})
	if err != nil {
		log.Fatal(err)
	}
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
	result, searchErr := c.Search(ctx, ad.SearchOptions{Base: *base, Scope: ad.ScopeSubtree, TypedFilter: filter, Properties: []string{"objectGUID", "sn"}})
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
