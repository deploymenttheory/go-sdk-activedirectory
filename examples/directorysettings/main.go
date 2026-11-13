// Directorysettings reads by default; writes require explicit operation/apply.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	server := flag.String("server", "", "explicit LDAP server DNS name")
	operation := flag.String("operation", "read", "read, domain-days, forest-upn, domain-mode, or forest-mode")
	value := flag.String("value", "", "integer days/level, or comma-separated replacement UPN suffixes (empty clears)")
	apply := flag.Bool("apply", false, "explicitly execute the selected write")
	lower := flag.Bool("allow-lowering", false, "explicitly allow a supported functional-level rollback")
	flag.Parse()
	if *server == "" || (*operation != "read" && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *operation, *value, *lower); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(server, operation, value string, lower bool) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	root, err := client.RootDSE(ctx, ad.RootDSEOptions{})
	if err != nil {
		return err
	}
	if operation == "read" {
		domain, domainErr := client.Directory().Domain(ctx, ad.DomainOptions{})
		forest, forestErr := client.Directory().Forest(ctx)
		fmt.Printf("domain=%s allowed-dns=%v interval-days=%v rolling=%v\n", domain.Raw.DistinguishedName, domain.AllowedDNSSuffixes, display(domain.LogonTimeSyncInterval), display(domain.PublicKeyRequiredPasswordRolling))
		fmt.Printf("forest-upn=%v forest-spn=%v domain-level=%v forest-level=%v\n", forest.UPNSuffixes, forest.SPNSuffixes, display(domain.FunctionalLevel), display(forest.FunctionalLevel))
		return errors.Join(domainErr, forestErr)
	}
	if root.DefaultNamingContext == nil || root.ConfigurationNamingContext == nil {
		return ad.ErrInvalidResult
	}
	domain, err := ad.IdentityByDN(*root.DefaultNamingContext)
	if err != nil {
		return err
	}
	forest, err := ad.IdentityByDN("CN=Partitions," + *root.ConfigurationNamingContext)
	if err != nil {
		return err
	}
	var result ad.ObjectMutationResult
	if operation == "forest-upn" {
		var suffixes []string
		if value != "" {
			suffixes = strings.Split(value, ",")
		}
		result, err = client.UpdateForest(ctx, ad.UpdateForestRequest{Identity: forest, UPNSuffixes: &suffixes})
	} else {
		parsed, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil {
			return parseErr
		}
		switch operation {
		case "domain-days":
			days := uint32(parsed)
			result, err = client.UpdateDomain(ctx, ad.UpdateDomainRequest{Identity: domain, LastLogonReplicationIntervalDays: &days})
		case "domain-mode", "forest-mode":
			request := ad.FunctionalLevelTransitionRequest{Identity: domain, Level: ad.FunctionalLevel(parsed), AllowLowering: lower}
			var transition ad.FunctionalLevelTransitionResult
			if operation == "forest-mode" {
				request.Identity = forest
				transition, err = client.SetForestMode(ctx, request)
			} else {
				transition, err = client.SetDomainMode(ctx, request)
			}
			result = transition.Mutation
			fmt.Printf("current=%v target=%d preflight-complete=%t unchanged=%t role=%s\n", display(transition.Current), transition.Requested, transition.PreflightComplete, transition.Unchanged, transition.Role)
		default:
			return fmt.Errorf("unknown operation %q", operation)
		}
	}
	fmt.Printf("state=%d readback=%t verified=%t\n", result.State, result.ReadbackComplete, result.Verified)
	return err // Never replay an uncertain or unverified write.
}

func display[T any](value *T) any {
	if value == nil {
		return "unavailable"
	}
	return *value
}
