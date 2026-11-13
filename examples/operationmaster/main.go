// This example changes FSMO ownership. Use only in a disposable test forest
// until the qualification described in docs/operation-master.md is complete.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func run(server string, port uint, roleNames string, force bool) (err error) {
	if port == 0 || port > 65535 {
		return ad.ErrInvalidConfig
	}
	request := ad.MoveOperationMasterRolesRequest{Force: force}
	for _, role := range strings.Split(roleNames, ",") {
		request.Roles = append(request.Roles, ad.OperationMasterRole(strings.TrimSpace(role)))
	}
	if err := request.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server, Port: uint16(port)}, Timeout: 2 * time.Minute})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	result, err := client.MoveOperationMasterRoles(ctx, request)
	fmt.Printf("Target DSA: %s\n", result.TargetDSA)
	for _, outcome := range result.Outcomes {
		fmt.Printf("%s: %s, verified=%t, observed owner=%s, error=%v\n", outcome.Role, outcome.Status, outcome.Verified, outcome.ObservedOwnerDN, outcome.Err)
		if outcome.RequestedRIDPool != nil {
			fmt.Printf("  Requested RID pool: %d\n", *outcome.RequestedRIDPool)
		}
		if outcome.ObservedRIDPool != nil {
			fmt.Printf("  Observed RID pool: %d\n", *outcome.ObservedRIDPool)
		}
	}
	return err
}

func main() {
	server := flag.String("server", "", "target LDAP server FQDN")
	port := flag.Uint("port", 389, "target LDAP port (use the instance port for AD LDS)")
	roles := flag.String("roles", "", "comma-separated roles: PDCEmulator,RIDMaster,InfrastructureMaster,SchemaMaster,DomainNamingMaster")
	force := flag.Bool("force", false, "permit seizure after a definite transfer failure; RID seizure consumes 30,000 RIDs")
	flag.Parse()
	if err := run(*server, *port, *roles, *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
