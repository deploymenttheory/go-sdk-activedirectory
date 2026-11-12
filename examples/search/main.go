package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	server := flag.String("server", "", "fully qualified LDAP server")
	base := flag.String("base", "", "search base distinguished name")
	flag.Parse()
	if *server == "" || *base == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *base); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, base string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := client.Close(); err == nil {
			err = closeErr
		}
	}()
	result, searchErr := client.Search(ctx, ad.SearchOptions{Base: base, Scope: ad.ScopeSubtree, Filter: "(objectClass=*)", Properties: []string{"name", "objectGUID", "description"}, PageSize: 256, ResultLimit: 100})
	for _, object := range result.Objects {
		fmt.Println(object.DistinguishedName)
		if values, state := object.Attribute("objectGUID"); state == ad.AttributePresent {
			fmt.Println("  raw GUID bytes:", base64.StdEncoding.EncodeToString(values[0]))
		}
	}
	fmt.Printf("Complete: %v; caller limit reached: %v\n", result.Complete, result.LimitReached)
	return searchErr
}
