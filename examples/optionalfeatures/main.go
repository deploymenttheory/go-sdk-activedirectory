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

func run(server string, port uint, action string, request ad.OptionalFeatureChangeRequest) (err error) {
	if port == 0 || port > 65535 || (action != "read" && action != "enable" && action != "disable") {
		return ad.ErrInvalidOptionalFeature
	}
	if action != "read" {
		if err := request.Validate(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := ad.Dial(ctx, ad.Config{Endpoint: ad.Endpoint{Host: server, Port: uint16(port)}, Timeout: 2 * time.Minute})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if action == "read" {
		result, readErr := client.OptionalFeatures(ctx, ad.OptionalFeatureQuery{FeatureGUID: request.FeatureGUID})
		return errors.Join(readErr, encoder.Encode(result))
	}
	var result ad.OptionalFeatureChangeResult
	if action == "enable" {
		result, err = client.EnableOptionalFeature(ctx, request)
	} else {
		result, err = client.DisableOptionalFeature(ctx, request)
	}
	fmt.Printf("Feature=%s scope=%s write=%d verified=%t\n", request.FeatureGUID, result.ScopeDN, result.WriteState, result.Verified)
	return err
}

func main() {
	server := flag.String("server", "", "explicit LDAP server FQDN; naming master for forest/configuration changes")
	port := flag.Uint("port", 389, "LDAP port (AD LDS instance port when applicable)")
	action := flag.String("action", "read", "read, enable or disable; read is the default")
	guid := flag.String("feature-guid", "", "feature GUID; empty reads all features")
	scope := flag.String("scope", "", "ForestOrConfigurationSet, Domain or Server")
	scopeDN := flag.String("scope-dn", "", "exact scope object distinguished name")
	ack := flag.Bool("acknowledge-irreversible", false, "explicitly authorize an enable that cannot be undone")
	flag.Parse()
	if err := run(*server, *port, *action, ad.OptionalFeatureChangeRequest{FeatureGUID: *guid, Scope: ad.OptionalFeatureScope(*scope), ScopeDN: *scopeDN, AcknowledgeIrreversible: *ack}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
