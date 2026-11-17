//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type InternalLdsSearchInput struct {
	Server, Partition, BindDN, Marker string
	SSLPort, ReplicaSSLPort           uint16
	Password                          []byte
}

func InternalReadLDSSearchInput(reader io.Reader) (InternalLdsSearchInput, error) {
	var input InternalLdsSearchInput
	payload, err := io.ReadAll(io.LimitReader(reader, 16385))
	defer clear(payload)
	invalid := errors.New("invalid isolated LDS search input")
	if err != nil || len(payload) > 16384 {
		return input, invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&input); err == nil {
		err = decoder.Decode(new(any))
	}
	if !errors.Is(err, io.EOF) ||
		!strings.HasSuffix(strings.ToLower(input.Server), ".ad.sdk.test") ||
		input.Partition != "CN=SdkLds,DC=lab,DC=test" ||
		input.BindDN != "CN=SDKReader,"+input.Partition ||
		!strings.HasPrefix(input.Marker, "ad-sdk-lds:") ||
		input.SSLPort == 0 ||
		input.ReplicaSSLPort == 0 ||
		input.SSLPort == input.ReplicaSSLPort ||
		len(input.Password) == 0 {
		clear(input.Password)
		return InternalLdsSearchInput{}, invalid
	}
	return input, nil
}

// Read-only qualification of the already owned application partition. A native
// LDS reader is sent through redirected stdin, and the same reader is used by
// the PowerShell-hosted System.DirectoryServices.Protocols reference.
func TestADLDSSearchLab(t *testing.T) {
	if os.Getenv("ADSDK_LDS_SEARCH_LAB") != "1" {
		t.Skip("requires the owned LDS partition and redirected reader input")
	}
	input, err := InternalReadLDSSearchInput(os.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(input.Password)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rows := make([]map[string]any, 0, 2)
	for index, port := range []uint16{input.SSLPort, input.ReplicaSSLPort} {
		config := admodel.Config{
			Endpoint:       admodel.Endpoint{Host: input.Server, Port: port},
			Transport:      admodel.TransportLDAPS,
			Authentication: admodel.AuthenticationSimple,
			Partition:      input.Partition,
			Credentials:    &admodel.Credentials{Username: input.BindDN, Password: input.Password},
			Timeout:        10 * time.Second,
		}
		client, err := adengine.Dial(ctx, config)
		if err != nil {
			t.Fatal("LDS reader could not bind to its explicit TLS endpoint")
		}
		defer client.Close()
		var counts InternalSearchNativeCounts
		(*adengine.InternalClientSessionPointer(client)).(*adengine.InternalLdapSession).InternalApi = InternalCountedSearchAPI(
			&counts,
		)
		root, err := client.RootDSE(ctx, admodel.RootDSEOptions{})
		if err != nil || root.Capabilities().Type != admodel.DirectoryADLDS ||
			!slices.Contains(root.SupportedControls, "1.2.840.113556.1.4.319") {
			t.Fatal("LDS/paging capabilities are absent from the configured endpoint")
		}
		if err := root.Capabilities().
			RequireADDS("search qualification DS-only prerequisite"); !errors.Is(err, admodel.ErrUnsupportedDirectory) ||
			InternalHasLDAPCode(err, 50) {
			t.Fatal("directory capability rejection was confused with permission denial")
		}
		partition, err := client.Partition(ctx)
		if err != nil || !strings.EqualFold(partition.DistinguishedName, input.Partition) {
			t.Fatal("explicit LDS application partition was not selected")
		}
		self, err := client.Search(
			ctx,
			admodel.SearchOptions{Base: input.BindDN, Properties: []string{"description"}},
		)
		if err != nil || !self.Complete || len(self.Objects) != 1 {
			t.Fatal("owned LDS reader is not visible")
		}
		marker, markerState := self.Objects[0].Attribute("description")
		if markerState != admodel.AttributePresent || len(marker) != 1 ||
			string(marker[0]) != input.Marker {
			t.Fatal("LDS reader belongs to a different fixture")
		}
		properties := []string{"objectGUID", "objectClass", "description"}
		options := admodel.SearchOptions{
			Base:       partition.DistinguishedName,
			Scope:      admodel.ScopeOneLevel,
			PageSize:   1,
			Properties: properties,
		}
		one, err := client.Search(ctx, options)
		if err != nil || !one.Complete || len(one.Objects) < 2 {
			t.Fatal("LDS one-level search did not traverse multiple pages")
		}
		for _, object := range one.Objects {
			guid, state := object.Attribute("objectGUID")
			if state != admodel.AttributePresent || len(guid) != 1 || len(guid[0]) != 16 {
				t.Fatal("LDS objectGUID lost its binary representation")
			}
			if _, state := object.Attribute("whenCreated"); state != admodel.AttributeUnloaded {
				t.Fatal("LDS unrequested property was treated as loaded")
			}
		}
		options.Scope = admodel.ScopeSubtree
		subtree, err := client.Search(ctx, options)
		if err != nil || !subtree.Complete || len(subtree.Objects) <= len(one.Objects) {
			t.Fatal("LDS subtree did not include the partition and descendants")
		}
		base, err := client.Search(
			ctx,
			admodel.SearchOptions{Base: input.Partition, Properties: properties, PageSize: 1},
		)
		if err != nil || !base.Complete || len(base.Objects) != 1 ||
			!strings.EqualFold(base.Objects[0].DistinguishedName, input.Partition) {
			t.Fatal("LDS base scope did not select the explicit partition")
		}
		options.Scope, options.ResultLimit = admodel.ScopeOneLevel, 1
		limited, err := client.Search(ctx, options)
		if err != nil || limited.Complete || !limited.LimitReached || len(limited.Objects) != 1 {
			t.Fatal("LDS caller limit or cursor cleanup failed")
		}
		options.ResultLimit, options.Filter = 0, "(objectClass=ADSDKSearchNoSuchClass)"
		zero, err := client.Search(ctx, options)
		if err != nil || !zero.Complete || len(zero.Objects) != 0 {
			t.Fatal("LDS zero-match search failed")
		}
		_, missing := client.Search(
			ctx,
			admodel.SearchOptions{Base: "CN=ADSDK-Search-Missing," + input.Partition},
		)
		if !InternalHasLDAPCode(missing, 32) || !errors.Is(missing, admodel.ErrIncompleteResult) {
			t.Fatal("LDS missing base did not preserve its LDAP status")
		}
		if err := client.Close(); err != nil || counts != (InternalSearchNativeCounts{}) {
			t.Fatal("LDS search native allocations were not released")
		}
		// Resolve the instance default independently. Its absence must not prevent
		// a search that explicitly supplies a base on the same connection.
		config.Partition = ""
		unselected, err := adengine.Dial(ctx, config)
		if err != nil {
			t.Fatal("LDS default-partition probe could not bind")
		}
		defer unselected.Close()
		(*adengine.InternalClientSessionPointer(unselected)).(*adengine.InternalLdapSession).InternalApi = InternalCountedSearchAPI(
			&counts,
		)
		selected, selectionErr := unselected.Partition(ctx)
		if index == 0 &&
			(selectionErr != nil || !strings.EqualFold(selected.DistinguishedName, input.Partition)) {
			t.Fatal("primary LDS default partition differs")
		}
		if index == 1 && !errors.Is(selectionErr, admodel.ErrNoDefaultPartition) {
			t.Fatal("replica unexpectedly inferred a default partition")
		}
		explicit, err := unselected.Search(
			ctx,
			admodel.SearchOptions{
				Base:       input.Partition,
				Scope:      admodel.ScopeOneLevel,
				PageSize:   1,
				Properties: properties,
			},
		)
		if closeErr := unselected.Close(); err != nil || closeErr != nil || !explicit.Complete ||
			len(explicit.Objects) != len(one.Objects) ||
			counts != (InternalSearchNativeCounts{}) {
			t.Fatal("explicit LDS search base depended on an instance default")
		}
		rows = append(
			rows,
			map[string]any{
				"port":                                   port,
				"partition":                              partition.DistinguishedName,
				"directory_type":                         "AD LDS",
				"paging_supported":                       true,
				"adds_prerequisite_rejected":             true,
				"default_partition_absent":               index == 1,
				"explicit_base_without_config_partition": true,
				"base":                                   base.Objects,
				"one_level":                              one.Objects,
				"subtree":                                subtree.Objects,
				"limited":                                limited.Objects,
				"limit_reached":                          limited.LimitReached,
				"zero_count":                             0,
				"missing_base_code":                      32,
				"native_allocations_released":            true,
			},
		)
	}
	encoded, err := json.MarshalIndent(
		map[string]any{
			"passed":           true,
			"server":           input.Server,
			"bind_dn":          input.BindDN,
			"partition":        input.Partition,
			"reads":            rows,
			"fixture_retained": true,
		},
		"",
		"  ",
	)
	if err != nil {
		t.Fatal(err)
	}
	path := os.Getenv("ADSDK_LDS_SEARCH_RESULT")
	if path == "" {
		t.Fatal("missing nonsecret LDS search result destination")
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLDSSearchInputBoundaries(t *testing.T) {
	valid := `{"Server":"member.ad.sdk.test","Partition":"CN=SdkLds,DC=lab,DC=test","BindDN":"CN=SDKReader,CN=SdkLds,DC=lab,DC=test","Marker":"ad-sdk-lds:owned","SSLPort":51301,"ReplicaSSLPort":51401,"Password":"c2VjcmV0"}`
	input, err := InternalReadLDSSearchInput(strings.NewReader(valid))
	if err != nil || string(input.Password) != "secret" {
		t.Fatal("valid redirected LDS input rejected")
	}
	clear(input.Password)
	for _, payload := range []string{valid + `{}`, strings.Repeat(" ", 16385), strings.Replace(valid, `"Password":`, `"unknown":0,"Password":`, 1), strings.Replace(valid, "member.ad.sdk.test", "outside.invalid", 1), strings.ReplaceAll(valid, "CN=SdkLds", "CN=Other"), strings.Replace(valid, "SDKReader", "Administrator", 1), strings.Replace(valid, "51401", "51301", 1), strings.Replace(valid, "c2VjcmV0", "", 1)} {
		input, err = InternalReadLDSSearchInput(strings.NewReader(payload))
		if err == nil || len(input.Password) != 0 || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid LDS input was accepted or disclosed")
		}
	}
}
