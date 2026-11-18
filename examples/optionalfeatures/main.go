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
	addirectorysettings "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/directory_settings"
	"github.com/deploymenttheory/go-sdk-activedirectory/examples/internal/secureauth"
)

func run(
	server string,
	port uint,
	action string,
	request addirectorysettings.OptionalFeatureChangeRequest,
) (err error) {
	if port > 65535 ||
		(action != "read" && action != "enable" && action != "disable") {
		return addirectorysettings.ErrInvalidOptionalFeature
	}
	if action != "read" {
		if err := request.Validate(); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config, err := secureauth.Config(ad.Endpoint{Host: server, Port: uint16(port)})
	if err != nil {
		return err
	}
	config.Timeout = 2 * time.Minute
	client, err := ad.Dial(ctx, config)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, client.Close()) }()
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if action == "read" {
		result, readErr := client.DirectorySettings.OptionalFeatures(
			ctx,
			addirectorysettings.OptionalFeatureQuery{FeatureGUID: request.FeatureGUID},
		)
		return errors.Join(readErr, encoder.Encode(result))
	}
	var result addirectorysettings.OptionalFeatureChangeResult
	if action == "enable" {
		result, err = client.DirectorySettings.EnableOptionalFeature(ctx, request)
	} else {
		result, err = client.DirectorySettings.DisableOptionalFeature(ctx, request)
	}
	fmt.Printf(
		"Feature=%s scope=%s write=%d verified=%t\n",
		request.FeatureGUID,
		result.ScopeDN,
		result.WriteState,
		result.Verified,
	)
	return err
}

func main() {
	server := flag.String(
		"server",
		"",
		"explicit LDAP server FQDN; naming master for forest/configuration changes",
	)
	port := flag.Uint("port", 0, "target port; 0 selects the secure transport default")
	action := flag.String("action", "read", "read, enable or disable; read is the default")
	guid := flag.String("feature-guid", "", "feature GUID; empty reads all features")
	scope := flag.String("scope", "", "ForestOrConfigurationSet, Domain or Server")
	scopeDN := flag.String("scope-dn", "", "exact scope object distinguished name")
	ack := flag.Bool(
		"acknowledge-irreversible",
		false,
		"explicitly authorize an enable that cannot be undone",
	)
	flag.Parse()
	if err := run(
		*server,
		*port,
		*action,
		addirectorysettings.OptionalFeatureChangeRequest{
			FeatureGUID:             *guid,
			Scope:                   addirectorysettings.OptionalFeatureScope(*scope),
			ScopeDN:                 *scopeDN,
			AcknowledgeIrreversible: *ack,
		},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
