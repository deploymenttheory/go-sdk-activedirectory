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

func run(server, kind, scope, site string) error {
	selection := ad.ReplicationSelection{SiteName: site}
	switch scope {
	case "server":
		selection.Scope = ad.ReplicationScopeServer
	case "domain":
		selection.Scope = ad.ReplicationScopeDomain
	case "forest":
		selection.Scope = ad.ReplicationScopeForest
	case "site":
		selection.Scope = ad.ReplicationScopeSite
	default:
		return errors.New("scope must be server, domain, forest or site")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config := ad.Config{Endpoint: ad.Endpoint{Host: server}}
	var result any
	var err error
	switch kind {
	case "partners":
		result, err = ad.ReadReplicationPartners(ctx, config, ad.ReplicationPartnerQuery{Selection: selection, Direction: ad.ReplicationBoth})
	case "failures":
		result, err = ad.ReadReplicationFailures(ctx, config, ad.ReplicationFailureQuery{Selection: selection})
	case "queue":
		result, err = ad.ReadReplicationQueue(ctx, config, ad.ReplicationQueueQuery{Selection: selection})
	default:
		return errors.New("kind must be partners, failures or queue")
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return errors.Join(err, encoder.Encode(result))
}

func main() {
	server := flag.String("server", "", "fully qualified LDAP anchor hostname")
	kind := flag.String("kind", "partners", "partners, failures or queue")
	scope := flag.String("scope", "server", "server, domain, forest or site")
	site := flag.String("site", "", "exact site name for site scope")
	flag.Parse()
	if err := run(*server, *kind, *scope, *site); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
