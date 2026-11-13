package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

func run() error {
	server := flag.String("server", "", "LDAP anchor FQDN")
	object := flag.String("object", "", "exact object DN; empty reads vectors")
	partition := flag.String("partition", "", "vector naming context; empty reads all hosted NCs")
	properties := flag.String("properties", "", "comma-separated exact attribute names; empty selects all")
	links := flag.Bool("links", false, "include per-linked-value metadata")
	deleted := flag.Bool("deleted", false, "include deleted objects and deactivated links (use with -links)")
	scope := flag.String("scope", "server", "server, domain, forest, or site")
	site := flag.String("site", "", "site name for site scope")
	flag.Parse()
	selection := ad.ReplicationSelection{SiteName: *site}
	switch *scope {
	case "server":
		selection.Scope = ad.ReplicationScopeServer
	case "domain":
		selection.Scope = ad.ReplicationScopeDomain
	case "forest":
		selection.Scope = ad.ReplicationScopeForest
	case "site":
		selection.Scope = ad.ReplicationScopeSite
	default:
		return errors.New("invalid scope")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config := ad.Config{Endpoint: ad.Endpoint{Host: *server}}
	var result any
	var err error
	if *object != "" {
		query := ad.ReplicationAttributeMetadataQuery{Selection: selection, ObjectDN: *object, IncludeLinkedValues: *links, IncludeDeletedObjects: *deleted, IncludeDeactivatedLinks: *deleted && *links}
		if *properties != "" {
			query.Properties = strings.Split(*properties, ",")
		}
		result, err = ad.ReadReplicationAttributeMetadata(ctx, config, query)
	} else {
		query := ad.ReplicationVectorQuery{Selection: selection}
		if *partition != "" {
			query.PartitionDNs = []string{*partition}
		}
		result, err = ad.ReadReplicationUpToDatenessVectors(ctx, config, query)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return errors.Join(err, encoder.Encode(result))
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
