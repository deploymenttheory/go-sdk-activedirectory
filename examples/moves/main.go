// Moves uses one LDAP ModifyDN with explicit endpoints and protected clients.
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
	server := flag.String(
		"source-server",
		"",
		"explicit source LDAP server (RID master for cross-domain)",
	)
	port := flag.Uint("port", 0, "source port; 0 selects the secure transport default")
	target := flag.String(
		"destination-server",
		"",
		"explicit destination RID master; empty means local move",
	)
	targetPort := flag.Uint("destination-port", 0, "destination port; 0 selects the secure transport default")
	targetAuth := destinationAuthentication{}
	flag.StringVar(&targetAuth.realm, "destination-realm", "", "optional independent target Kerberos realm; requires user and exactly one keytab/cache")
	flag.StringVar(&targetAuth.username, "destination-user", "", "independent target read-only actor")
	flag.StringVar(&targetAuth.keytab, "destination-keytab", "", "caller-owned target keytab; no password arguments")
	flag.StringVar(&targetAuth.cache, "destination-cache", "", "caller-owned target Kerberos FILE cache")
	dn := flag.String("dn", "", "source object DN; select exactly one of dn or guid")
	guid := flag.String("guid", "", "source object GUID")
	parent := flag.String("parent", "", "existing destination parent DN")
	partition := flag.String("partition", "", "explicit source naming context")
	delegate := flag.Bool(
		"delegate",
		false,
		"explicitly permit source Kerberos delegation for cross-domain move",
	)
	apply := flag.Bool("apply", false, "submit exactly one move")
	flag.Parse()
	if !*apply || *server == "" || *parent == "" || (*dn == "") == (*guid == "") ||
		*port > 65535 ||
		*targetPort > 65535 ||
		(*target != "" && !*delegate) ||
		(*target == "" && (*delegate || targetAuth != (destinationAuthentication{}))) {
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
		err = run(*server, uint16(*port), *target, uint16(*targetPort), *delegate, targetAuth, request)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(
	server string,
	port uint16,
	target string,
	targetPort uint16,
	delegate bool,
	targetAuth destinationAuthentication,
	request ad.MoveObjectRequest,
) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	config, err := secureauth.Config(ad.Endpoint{Host: server, Port: port})
	if err != nil {
		return err
	}
	config.AllowDelegation, config.Timeout = delegate, 60*time.Second
	source, err := ad.Dial(ctx, config)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	if target != "" {
		var destination *ad.Client
		targetConfig, configErr := secureauth.Config(ad.Endpoint{Host: target, Port: targetPort})
		if configErr != nil {
			return configErr
		}
		if configErr = targetAuth.apply(&targetConfig); configErr != nil {
			return configErr
		}
		targetConfig.Timeout = 60 * time.Second
		destination, err = ad.Dial(ctx, targetConfig)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, destination.Close()) }()
		request.Destination = destination.Directory
	}
	result, err := source.Directory.MoveObject(ctx, request)
	guid := ""
	if result.Mutation.TargetGUID != nil {
		guid = result.Mutation.TargetGUID.String()
	}
	fmt.Printf(
		"state=%d verified=%t partial-effects-possible=%t guid=%s source=%s destination=%s delegation-complete=%t\n",
		result.Mutation.State,
		result.Mutation.Verified,
		result.Mutation.PartialEffectsPossible,
		guid,
		result.Mutation.Source.Host,
		result.Mutation.TargetDN,
		result.Security.Complete,
	)
	return err
}

type destinationAuthentication struct {
	realm, username, keytab, cache string
}

func (a destinationAuthentication) apply(config *ad.Config) error {
	if a == (destinationAuthentication{}) {
		return nil
	}
	if config.Backend != ad.BackendPortable || config.Authentication != ad.AuthenticationKerberos || a.realm == "" || a.username == "" ||
		(a.keytab == "") == (a.cache == "") {
		return fmt.Errorf("%w: independent destination requires portable Kerberos, explicit realm/user and exactly one keytab or cache", ad.ErrInvalidConfig)
	}
	credentials := &ad.KerberosCredentials{Username: a.username, Realm: a.realm, SPN: "ldap/" + config.Endpoint.Host}
	if a.keytab != "" {
		credentials.Source, credentials.KeytabPath = ad.KerberosKeytabFile, a.keytab
	} else {
		credentials.Source, credentials.CachePath = ad.KerberosCredentialCacheFile, a.cache
	}
	config.Kerberos = credentials
	return config.Validate()
}
