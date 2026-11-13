// Service-account directory lifecycle only; no local installation or secrets.
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
	server := flag.String("server", "", "explicit DC DNS name")
	dn := flag.String("dn", "", "account DN; optional parent DN for creation")
	operation := flag.String("operation", "read", "read, create-gmsa, create-outbound, create-smsa, delete")
	name := flag.String("name", "", "literal account name for creation")
	dns := flag.String("dns", "", "DNS host name for normal gMSA creation")
	reader := flag.String("reader", "", "existing computer/security-group DN allowed to retrieve the gMSA password")
	apply := flag.Bool("apply", false, "execute one explicit directory mutation")
	flag.Parse()
	if *server == "" || (*operation != "read" && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *operation, *name, *dns, *reader); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(server, dn, operation, name, dns, reader string) (err error) {
	var identity ad.Identity
	if dn != "" {
		identity, err = ad.IdentityByDN(dn)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	switch operation {
	case "read":
		result, e := client.ServiceAccount(ctx, identity, ad.ResolveIdentityOptions{})
		if result.Account != nil {
			fmt.Printf("dn=%s kind=%d complete=%t\n", result.Account.DistinguishedName, result.Account.Kind, result.Observation.Complete)
		}
		return e
	case "delete":
		result, e := client.DeleteServiceAccount(ctx, ad.DeleteServiceAccountRequest{Identity: identity})
		fmt.Printf("state=%d verified=%t\n", result.Mutation.State, result.Mutation.Verified)
		return e
	case "create-gmsa", "create-outbound", "create-smsa":
		request := ad.CreateServiceAccountRequest{Kind: ad.ServiceAccountGroupManaged, Parent: identity, Name: name}
		if operation == "create-smsa" {
			request.Kind = ad.ServiceAccountStandalone
		} else if operation == "create-outbound" {
			request.OutboundAuthenticationOnly = true
		} else {
			request.Properties.DNSHostName = &dns
		}
		if reader != "" {
			id, e := ad.IdentityByDN(reader)
			if e != nil {
				return e
			}
			request.PasswordReaders = []ad.Identity{id}
		}
		result, e := client.CreateServiceAccount(ctx, request)
		fmt.Printf("creation-state=%d verified=%t complete=%t\n", result.Creation.State, result.Creation.Verified, result.Complete)
		return e
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
}
