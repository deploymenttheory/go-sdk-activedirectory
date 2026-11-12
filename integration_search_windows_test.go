//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// scripts/lab/reference-search.ps1 owns this fixture: seven direct containers,
// one nested container, and no displayName attributes. Ordinary test runs skip.
func TestSearchLab(t *testing.T) {
	server, base := os.Getenv("ADSDK_SEARCH_SERVER"), os.Getenv("ADSDK_SEARCH_BASE")
	if server == "" {
		t.Skip("requires an explicitly configured isolated AD search fixture")
	}
	if base == "" {
		t.Fatal("search fixture base is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client, err := Dial(ctx, Config{Endpoint: Endpoint{Host: server}, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	root, err := client.RootDSE(ctx, RootDSEOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var counts searchNativeCounts
	client.session.(*ldapSession).api = countedSearchAPI(&counts)
	options := SearchOptions{Base: base, Scope: ScopeOneLevel, Filter: "(objectClass=container)", PageSize: 2, Properties: []string{"name", "objectGUID", "description", "displayName"}}
	all, err := client.Search(ctx, options)
	if err != nil || !all.Complete || len(all.Objects) != 7 {
		t.Fatalf("one-level search: count=%d complete=%v err=%v", len(all.Objects), all.Complete, err)
	}
	for _, object := range all.Objects {
		guid, state := object.Attribute("objectGUID")
		if state != AttributePresent || len(guid) != 1 || len(guid[0]) != 16 {
			t.Fatal("objectGUID binary value missing")
		}
		if _, state := object.Attribute("displayName"); state != AttributeAbsent {
			t.Fatal("explicit absent selection lost")
		}
		if _, state := object.Attribute("whenCreated"); state != AttributeUnloaded {
			t.Fatal("unrequested property was loaded")
		}
	}
	baseResult, err := client.Search(ctx, SearchOptions{Base: base, Scope: ScopeBase, Properties: []string{"1.1"}})
	if err != nil || len(baseResult.Objects) != 1 || !strings.EqualFold(baseResult.Objects[0].DistinguishedName, base) || len(baseResult.Objects[0].Attributes) != 0 {
		t.Fatalf("base/DN-only search: %+v %v", baseResult, err)
	}
	subtreeOptions := options
	subtreeOptions.Scope = ScopeSubtree
	subtree, err := client.Search(ctx, subtreeOptions)
	if err != nil || !subtree.Complete || len(subtree.Objects) != 8 {
		t.Fatalf("subtree search count=%d err=%v", len(subtree.Objects), err)
	}
	zeroOptions := options
	zeroOptions.Filter = "(name=ADSDK-search-no-such-object)"
	zero, err := client.Search(ctx, zeroOptions)
	if err != nil || !zero.Complete || len(zero.Objects) != 0 {
		t.Fatalf("zero matches: %+v %v", zero, err)
	}
	limitedOptions := options
	limitedOptions.ResultLimit = 3
	limited, err := client.Search(ctx, limitedOptions)
	if err != nil || len(limited.Objects) != 3 || !limited.LimitReached || limited.Complete {
		t.Fatalf("limited search: %+v %v", limited, err)
	}
	_, missingErr := client.Search(ctx, SearchOptions{Base: "CN=ADSDK-search-missing," + base})
	if !hasLDAPCode(missingErr, 32) || !errors.Is(missingErr, ErrIncompleteResult) {
		t.Fatalf("missing base: %v", missingErr)
	}
	for i := 0; i < 25; i++ {
		result, err := client.Search(ctx, options)
		if err != nil || len(result.Objects) != 7 {
			t.Fatalf("repeated call %d: %v", i, err)
		}
		if counts != (searchNativeCounts{}) {
			t.Fatalf("unreleased allocations after iteration %d: %+v", i, counts)
		}
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	remaining := map[string]int{"messages": counts.messages, "request_controls": counts.controls, "response_controls": counts.controlSets, "cookies": counts.cookies, "values": counts.values, "names": counts.names, "attribute_cursors": counts.cursors}
	artifact := map[string]any{"passed": true, "server": server, "base": base, "objects": all.Objects, "subtree_count": len(subtree.Objects), "zero_count": len(zero.Objects), "limited_count": len(limited.Objects), "missing_base_code": 32, "repeated_calls": 25, "native_allocations_remaining": remaining, "rootdse": root.Attributes}
	if path := os.Getenv("ADSDK_SEARCH_RESULT"); path != "" {
		data, err := json.MarshalIndent(artifact, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
