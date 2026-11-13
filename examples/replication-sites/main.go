// Replication-sites reads by default; explicit writes require -apply.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func main() {
	server := flag.String("server", "", "explicit LDAP endpoint")
	op := flag.String("operation", "sites", "sites, subnets, site, subnet, create-site, create-subnet, set-site-description, set-subnet-site, delete-site, delete-subnet, move-server")
	dn := flag.String("dn", "", "explicit site/subnet/server/DSA distinguished name")
	siteDN := flag.String("site-dn", "", "explicit associated or destination site DN")
	name := flag.String("name", "", "literal new site name")
	prefix := flag.String("prefix", "", "canonical IPv4/IPv6 network prefix")
	description := flag.String("description", "", "site description")
	apply := flag.Bool("apply", false, "execute the selected mutation once")
	flag.Parse()
	read := *op == "sites" || *op == "subnets" || *op == "site" || *op == "subnet"
	if *server == "" || (!read && !*apply) {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *op, *dn, *siteDN, *name, *prefix, *description); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(server, operation, dn, siteDN, name, prefix, description string) (err error) {
	var identity ad.Identity
	if dn != "" {
		identity, err = ad.IdentityByDN(dn)
		if err != nil {
			return err
		}
	}
	var site *ad.Identity
	if siteDN != "" {
		value, e := ad.IdentityByDN(siteDN)
		if e != nil {
			return e
		}
		site = &value
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server}})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	var result any
	switch operation {
	case "sites":
		result, err = client.ReplicationSites(ctx, ad.SearchOptions{})
	case "subnets":
		result, err = client.ReplicationSubnets(ctx, ad.SearchOptions{})
	case "site":
		result, err = client.ReplicationSite(ctx, identity, ad.ResolveIdentityOptions{})
	case "subnet":
		result, err = client.ReplicationSubnet(ctx, identity, ad.ResolveIdentityOptions{})
	case "create-site":
		result, err = client.CreateReplicationSite(ctx, ad.CreateReplicationSiteRequest{Name: name, Description: &description})
	case "create-subnet":
		network, e := netip.ParsePrefix(prefix)
		if e != nil {
			return e
		}
		result, err = client.CreateReplicationSubnet(ctx, ad.CreateReplicationSubnetRequest{Prefix: network, Site: site})
	case "set-site-description":
		result, err = client.UpdateReplicationSite(ctx, ad.UpdateReplicationSiteRequest{Identity: identity, Description: &description})
	case "set-subnet-site":
		if site == nil {
			return ad.ErrInvalidIdentity
		}
		result, err = client.UpdateReplicationSubnet(ctx, ad.UpdateReplicationSubnetRequest{Identity: identity, Site: site})
	case "delete-site":
		result, err = client.DeleteReplicationSite(ctx, identity, ad.ObjectMutationOptions{})
	case "delete-subnet":
		result, err = client.DeleteReplicationSubnet(ctx, identity, ad.ObjectMutationOptions{})
	case "move-server":
		if site == nil {
			return ad.ErrInvalidIdentity
		}
		result, err = client.MoveDirectoryServer(ctx, ad.MoveDirectoryServerRequest{Server: identity, Site: *site})
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	data, encodeErr := json.MarshalIndent(result, "", "  ")
	if encodeErr == nil {
		fmt.Println(string(data))
	}
	return errors.Join(err, encodeErr)
}
