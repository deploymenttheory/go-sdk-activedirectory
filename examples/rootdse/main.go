package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func run(server, username, domain string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := ad.Config{Endpoint: ad.Endpoint{Host: server}}
	if err := config.Validate(); err != nil {
		return err
	}
	if username == "" && domain != "" {
		return errors.New("domain requires an explicit username")
	}
	if username != "" {
		info, err := os.Stdin.Stat()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeCharDevice != 0 {
			return errors.New("supply exact UTF-8 password bytes through redirected stdin; interactive password echo is disabled")
		}
		password, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
		defer clear(password)
		if err != nil {
			return err
		}
		if len(password) > 65536 {
			return errors.New("password input exceeds the example's 64 KiB input limit")
		}
		config.Credentials = &ad.Credentials{Username: username, Domain: domain, Password: password}
	}
	client, err := ad.Dial(ctx, config)
	if config.Credentials != nil {
		clear(config.Credentials.Password)
		config.Credentials = nil
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	root, err := client.RootDSE(ctx, ad.RootDSEOptions{})
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
	username := flag.String("username", "", "explicit account name; password is read from redirected stdin")
	domain := flag.String("domain", "", "explicit account domain")
	flag.Parse()
	if err := run(*server, *username, *domain); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
