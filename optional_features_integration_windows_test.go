//go:build integration && windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Explicit integration opt-in. This never provisions a fixture or restores,
// retries, or changes a feature other than the one named by the caller.
func TestOptionalFeatureLive(t *testing.T) {
	server := os.Getenv("AD_OPTIONAL_FEATURE_LAB_TARGET")
	if server == "" {
		t.Skip("requires an explicitly selected disposable directory")
	}
	action := os.Getenv("AD_OPTIONAL_FEATURE_LAB_ACTION")
	if action == "" {
		action = "read"
	}
	if action != "read" && action != "enable" && action != "disable" {
		t.Fatal("action must be read, enable or disable")
	}
	request := OptionalFeatureChangeRequest{FeatureGUID: os.Getenv("AD_OPTIONAL_FEATURE_LAB_GUID"), Scope: OptionalFeatureScope(os.Getenv("AD_OPTIONAL_FEATURE_LAB_SCOPE")), ScopeDN: os.Getenv("AD_OPTIONAL_FEATURE_LAB_SCOPE_DN"), AcknowledgeIrreversible: os.Getenv("AD_OPTIONAL_FEATURE_LAB_IRREVERSIBLE") == "acknowledge-irreversible"}
	if action != "read" {
		if os.Getenv("AD_OPTIONAL_FEATURE_LAB_ALLOW_CHANGES") != "disposable-directory" {
			t.Fatal("writes require AD_OPTIONAL_FEATURE_LAB_ALLOW_CHANGES=disposable-directory")
		}
		if err := request.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	wantGUID, err := optionalFeatureGUIDBytes(os.Getenv("AD_OPTIONAL_FEATURE_LAB_CONFIGURATION_GUID"))
	if err != nil {
		t.Fatal("pin the existing configuration object's GUID")
	}
	port := uint64(389)
	if value := os.Getenv("AD_OPTIONAL_FEATURE_LAB_PORT"); value != "" {
		port, err = strconv.ParseUint(value, 10, 16)
		if err != nil || port == 0 {
			t.Fatal("invalid port")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: server, Port: uint16(port)}, Timeout: 2 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	}()
	root, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil || root.ConfigurationNamingContext == nil {
		t.Fatal("configuration identity unavailable", err)
	}
	identity, err := client.Search(ctx, SearchOptions{Base: *root.ConfigurationNamingContext, Scope: ScopeBase, Properties: []string{"objectGUID"}})
	if err != nil || !identity.Complete || len(identity.Objects) != 1 {
		t.Fatal("cannot pin configuration identity", err)
	}
	values, state := identity.Objects[0].Attribute("objectGUID")
	if state != AttributePresent || len(values) != 1 || !strings.EqualFold(hex.EncodeToString(values[0]), hex.EncodeToString(wantGUID)) {
		t.Fatal("configuration GUID differs; no feature write submitted")
	}
	level := "unreported"
	if root.ForestFunctionality != nil {
		level = strconv.FormatUint(uint64(*root.ForestFunctionality), 10)
	}
	t.Logf("runtime=%s/%s endpoint=%s:%d directory=%s forest_level=%s action=%s", runtime.GOOS, runtime.GOARCH, server, port, root.Capabilities().Type, level, action)
	if action == "read" {
		result, err := client.OptionalFeatures(ctx, OptionalFeatureQuery{FeatureGUID: request.FeatureGUID})
		if err != nil || !result.Complete || len(result.Features) == 0 {
			t.Fatal("positive complete feature read required", err)
		}
		for _, feature := range result.Features {
			encoded, encodeErr := json.Marshal(feature)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			t.Logf("feature=%s", encoded)
		}
		return
	}
	var result OptionalFeatureChangeResult
	if action == "enable" {
		result, err = client.EnableOptionalFeature(ctx, request)
	} else {
		result, err = client.DisableOptionalFeature(ctx, request)
	}
	t.Logf("write=%d verified=%t feature=%s scope=%s", result.WriteState, result.Verified, request.FeatureGUID, result.ScopeDN)
	expect := os.Getenv("AD_OPTIONAL_FEATURE_LAB_EXPECT")
	if expect == "" || expect == "accepted" {
		if err != nil || result.WriteState != OptionalFeatureWriteAccepted || !result.Verified {
			t.Fatal("change not verified; reconcile before another write", err)
		}
		return
	}
	wanted := map[string]error{"prerequisite": ErrOptionalFeaturePrerequisite, "scope": ErrOptionalFeatureScope, "irreversible": ErrOptionalFeatureIrreversible, "permission": ErrOptionalFeaturePermission, "role": ErrOptionalFeatureRole}
	if wanted[expect] == nil || !errors.Is(err, wanted[expect]) || result.WriteState == OptionalFeatureWriteAccepted || result.WriteState == OptionalFeatureWriteUncertain {
		t.Fatalf("expected %s; state=%d err=%v", expect, result.WriteState, err)
	}
}
