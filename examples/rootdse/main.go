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

func run(server string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := secureauth.Dial(ctx, server)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	root, err := client.Directory.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil {
		return err
	}
	if root.DNSHostName != nil {
		fmt.Println("Server:", *root.DNSHostName)
	}
	if root.DefaultNamingContext != nil {
		fmt.Println("Default naming context:", *root.DefaultNamingContext)
	}
	fmt.Println("Naming contexts:", root.NamingContexts)
	fmt.Println("Advertised capabilities:", root.SupportedCapabilities)
	return nil
}

func main() {
	server := flag.String("server", "", "fully qualified LDAP server hostname")
	flag.Parse()
	if err := run(*server); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
