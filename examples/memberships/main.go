// Memberships performs reads only. No group membership changes are made.
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
	server := flag.String("server", "", "explicit full LDAP server")
	dn := flag.String("dn", "", "explicit group or account DN")
	operation := flag.String("operation", "group", "group, principal or authorization")
	gc := flag.String("gc-server", "", "optional explicit GC server; required for principal mode")
	recursive := flag.Bool("recursive", false, "return recursive leaf principals in group mode")
	flag.Parse()
	if *server == "" || *dn == "" || (*operation == "principal" && *gc == "") {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *dn, *operation, *gc, *recursive); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(server, dn, operation, gcServer string, recursive bool) (err error) {
	identity, err := ad.IdentityByDN(dn)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	var catalog *ad.Client
	if gcServer != "" {
		catalog, err = ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: gcServer, Port: 3268}})
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, catalog.Close()) }()
	}
	switch operation {
	case "group":
		result, readErr := client.GroupMembers(ctx, identity, ad.GroupMembersOptions{Recursive: recursive})
		fmt.Printf("members=%d complete=%t unresolved=%d\n", len(result.Members), result.Complete, len(result.Unresolved))
		for _, member := range result.Members {
			fmt.Println(member.Object.DistinguishedName)
		}
		return readErr
	case "principal":
		result, readErr := client.PrincipalGroupMembership(ctx, identity, ad.PrincipalGroupMembershipOptions{GlobalCatalog: catalog})
		fmt.Printf("groups=%d complete=%t\n", len(result.Groups), result.Complete)
		for _, group := range result.Groups {
			fmt.Println(group.DistinguishedName)
		}
		return readErr
	case "authorization":
		result, readErr := client.AccountAuthorizationGroups(ctx, identity, ad.AccountAuthorizationGroupsOptions{GlobalCatalog: catalog})
		fmt.Printf("SIDs=%d groups=%d tokens-complete=%t complete=%t\n", len(result.SIDs), len(result.Groups), result.TokensComplete, result.Complete)
		return readErr
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
}
