// Replication-links reads by default; explicit mutations require -apply.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

type identities []ad.Identity

func (i *identities) String() string { return fmt.Sprint([]ad.Identity(*i)) }
func (i *identities) Set(text string) error {
	value, err := ad.IdentityByDN(text)
	if err == nil {
		*i = append(*i, value)
	}
	return err
}
func main() {
	server := flag.String("server", "", "explicit LDAP endpoint")
	op := flag.String("operation", "links", "links, bridges, connections, link, bridge, connection, create-link, create-bridge, set-link-cost, set-bridge-members, disable-connection, delete-link, delete-bridge")
	dn := flag.String("dn", "", "explicit target distinguished name")
	name := flag.String("name", "", "literal new object name")
	transport := flag.String("transport", "IP", "IP or SMTP")
	cost := flag.Int("cost", 100, "link cost")
	apply := flag.Bool("apply", false, "submit the selected mutation once")
	var references identities
	flag.Var(&references, "reference-dn", "site/link DN; repeat for multiple references")
	flag.Parse()
	read := *op == "links" || *op == "bridges" || *op == "connections" || *op == "link" || *op == "bridge" || *op == "connection"
	if *server == "" || (!read && !*apply) || *cost < 0 || int64(*cost) > 2147483647 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*server, *op, *dn, *name, ad.ReplicationTransport(*transport), int32(*cost), references); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(server, operation, dn, name string, transport ad.ReplicationTransport, cost int32, references []ad.Identity) (err error) {
	var identity ad.Identity
	if dn != "" {
		identity, err = ad.IdentityByDN(dn)
		if err != nil {
			return err
		}
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
	case "links":
		result, err = client.ReplicationSiteLinks(ctx, transport, ad.SearchOptions{}, ad.ReplicationReferenceLimits{})
	case "bridges":
		result, err = client.ReplicationSiteLinkBridges(ctx, transport, ad.SearchOptions{}, ad.ReplicationReferenceLimits{})
	case "connections":
		result, err = client.ReplicationConnections(ctx, ad.SearchOptions{})
	case "link":
		result, err = client.ReplicationSiteLink(ctx, identity, ad.ReplicationLinkReadOptions{})
	case "bridge":
		result, err = client.ReplicationSiteLinkBridge(ctx, identity, ad.ReplicationLinkReadOptions{})
	case "connection":
		result, err = client.ReplicationConnection(ctx, identity, ad.ResolveIdentityOptions{})
	case "create-link":
		result, err = client.CreateReplicationSiteLink(ctx, ad.CreateReplicationSiteLinkRequest{Name: name, Transport: transport, Cost: &cost, Sites: references})
	case "create-bridge":
		result, err = client.CreateReplicationSiteLinkBridge(ctx, ad.CreateReplicationSiteLinkBridgeRequest{Name: name, Transport: transport, SiteLinks: references})
	case "set-link-cost":
		result, err = client.UpdateReplicationSiteLink(ctx, ad.UpdateReplicationSiteLinkRequest{Identity: identity, Cost: &cost})
	case "set-bridge-members":
		if references == nil {
			references = []ad.Identity{}
		}
		result, err = client.UpdateReplicationSiteLinkBridge(ctx, ad.UpdateReplicationSiteLinkBridgeRequest{Identity: identity, SiteLinks: ad.ReplicationReferenceChanges{Replace: references}})
	case "disable-connection":
		disabled := false
		result, err = client.UpdateReplicationConnection(ctx, ad.UpdateReplicationConnectionRequest{Identity: identity, Enabled: &disabled})
	case "delete-link":
		result, err = client.DeleteReplicationSiteLink(ctx, identity, ad.ObjectMutationOptions{})
	case "delete-bridge":
		result, err = client.DeleteReplicationSiteLinkBridge(ctx, identity, ad.ObjectMutationOptions{})
	default:
		return fmt.Errorf("unknown operation %q", operation)
	}
	encoded, encodeErr := json.MarshalIndent(result, "", "  ")
	if encodeErr == nil {
		fmt.Println(string(encoded))
	}
	return errors.Join(err, encodeErr)
}
