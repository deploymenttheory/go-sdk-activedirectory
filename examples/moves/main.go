// Moves uses native ModifyDN with explicit endpoints and caller-owned clients.
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
	server := flag.String("source-server", "", "explicit source LDAP server (RID master for cross-domain)")
	port := flag.Uint("port", 389, "source LDAP port, including an AD LDS instance port")
	target := flag.String("destination-server", "", "explicit destination RID master; empty means local move")
	targetPort := flag.Uint("destination-port", 389, "destination LDAP port")
	dn := flag.String("dn", "", "source object DN; select exactly one of dn or guid")
	guid := flag.String("guid", "", "source object GUID")
	parent := flag.String("parent", "", "existing destination parent DN")
	partition := flag.String("partition", "", "explicit source naming context")
	delegate := flag.Bool("delegate", false, "explicitly permit source Kerberos delegation for cross-domain move")
	apply := flag.Bool("apply", false, "submit exactly one move")
	flag.Parse()
	if !*apply || *server == "" || *parent == "" || (*dn == "") == (*guid == "") || *port == 0 || *port > 65535 || *targetPort == 0 || *targetPort > 65535 || (*target != "" && !*delegate) || (*target == "" && *delegate) {
		flag.Usage()
		os.Exit(2)
	}
	request := ad.MoveObjectRequest{Options: ad.ObjectMutationOptions{Partition: *partition}}
	var err error
	if *guid != "" {
		request.Identity, err = ad.IdentityByGUID(*guid)
	} else {
		request.Identity, err = ad.IdentityByDN(*dn)
	}
	if err == nil {
		request.TargetParent, err = ad.IdentityByDN(*parent)
	}
	if err == nil {
		err = run(*server, uint16(*port), *target, uint16(*targetPort), *delegate, request)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server string, port uint16, target string, targetPort uint16, delegate bool, request ad.MoveObjectRequest) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	source, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server, Port: port}, AllowDelegation: delegate, Timeout: 60 * time.Second})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	if target != "" {
		var destination *ad.Client
		destination, err = ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: target, Port: targetPort}, Timeout: 60 * time.Second})
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, destination.Close()) }()
		request.Destination = destination
	}
	result, err := source.MoveObject(ctx, request)
	fmt.Printf("state=%d verified=%t partial-effects-possible=%t destination=%s\n", result.Mutation.State, result.Mutation.Verified, result.Mutation.PartialEffectsPossible, result.Mutation.TargetDN)
	return err
}
