package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	adreplication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
	"github.com/deploymenttheory/go-sdk-activedirectory/examples/internal/secureauth"
)

func run(server, kind, scope, site, principalsFile string) error {
	selection := adreplication.ReplicationSelection{SiteName: site}
	if principalsFile != "" {
		file, err := os.Open(principalsFile)
		if err != nil {
			return errors.New("cannot open public replication principal map")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 128*1024+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > 128*1024 {
			return errors.New("cannot read bounded public replication principal map")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err = decoder.Decode(&selection.ServicePrincipals); err != nil {
			return errors.New("invalid replication principal map")
		}
		if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			return errors.New("exactly one replication principal map is required")
		}
	}
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
	principals := flag.String("principals", "", "public JSON map of explicit per-server LDAP, endpoint-map and DRS principals for portable RPC")
	flag.Parse()
	if err := run(*server, *kind, *scope, *site, *principals); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
