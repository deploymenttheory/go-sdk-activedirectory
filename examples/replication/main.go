package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adreplication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
	"github.com/deploymenttheory/go-sdk-activedirectory/examples/internal/secureauth"
)

func run(server, kind, scope, site string) error {
	selection := adreplication.ReplicationSelection{SiteName: site}
	switch scope {
	case "server":
		selection.Scope = adreplication.ReplicationScopeServer
	case "domain":
		selection.Scope = adreplication.ReplicationScopeDomain
	case "forest":
		selection.Scope = adreplication.ReplicationScopeForest
	case "site":
		selection.Scope = adreplication.ReplicationScopeSite
	default:
		return errors.New("scope must be server, domain, forest or site")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config, err := secureauth.Config(ad.Endpoint{Host: server})
	if err != nil {
		return err
	}
	var result any
	switch kind {
	case "partners":
		result, err = adreplication.ReadReplicationPartners(
			ctx,
			config,
			adreplication.ReplicationPartnerQuery{
				Selection: selection,
				Direction: adreplication.ReplicationBoth,
			},
		)
	case "failures":
		result, err = adreplication.ReadReplicationFailures(
			ctx,
			config,
			adreplication.ReplicationFailureQuery{Selection: selection},
		)
	case "queue":
		result, err = adreplication.ReadReplicationQueue(
			ctx,
			config,
			adreplication.ReplicationQueueQuery{Selection: selection},
		)
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
