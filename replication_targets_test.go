package activedirectory

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestReplicationScopeExpansion(t *testing.T) {
	for _, selection := range []ReplicationSelection{{Scope: ReplicationScopeDomain}, {Scope: ReplicationScopeDomain, DomainDNS: "example.test"}, {Scope: ReplicationScopeForest, ForestDNS: "example.test"}, {Scope: ReplicationScopeSite, SiteName: "London, UK"}} {
		f := newTopologyFixture()
		config := Config{Endpoint: Endpoint{Host: "dc1.example.test", Port: 1636}, Transport: TransportLDAPS}
		got, err := resolveReplicationTargets(context.Background(), config, selection, func(context.Context, Config) (*Client, error) { return f.client(time.Second), nil })
		if err != nil || !got.Complete || len(got.Servers) != 2 {
			t.Fatalf("scope %v: %+v err=%v", selection, got, err)
		}
		for _, endpoint := range got.Servers {
			if endpoint.Port != 636 {
				t.Fatalf("custom anchor port leaked into topology: %+v", endpoint)
			}
		}
		found := false
		for _, query := range f.queries {
			if query.Scope != ScopeSubtree {
				continue
			}
			found = true
			if strings.Contains(query.Filter, "msDS-HasDomainNCs=") != (selection.Scope == ReplicationScopeDomain) {
				t.Fatalf("scope %v filter %s", selection.Scope, query.Filter)
			}
			if selection.Scope == ReplicationScopeSite && query.Base != "CN=Servers,"+topSite {
				t.Fatalf("site base=%q", query.Base)
			}
		}
		if !found {
			t.Fatal("missing topology search")
		}
	}
}

func TestReplicationTargetPartialResolutionAndCapability(t *testing.T) {
	for _, mode := range []string{"partial", "lds", "missing-host", "wrong-forest"} {
		t.Run(mode, func(t *testing.T) {
			f := newTopologyFixture()
			selection := ReplicationSelection{Scope: ReplicationScopeForest}
			sentinel := errors.New("injected topology failure")
			switch mode {
			case "partial":
				f.pageFailureBase = topSites
				f.pageFailure = sentinel
			case "lds":
				f.root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
			case "missing-host":
				delete(f.objects[topServerRO].Attributes, "dnshostname")
			case "wrong-forest":
				selection.ForestDNS = "different.test"
			}
			got, err := resolveReplicationTargets(context.Background(), Config{Endpoint: Endpoint{Host: "dc1.example.test"}}, selection, func(context.Context, Config) (*Client, error) { return f.client(time.Second), nil })
			if err == nil || got.Complete {
				t.Fatalf("unreported uncertainty: %+v, %v", got, err)
			}
			if mode == "partial" && (len(got.Servers) != 2 || !errors.Is(err, sentinel)) {
				t.Fatalf("partial result lost: %+v, %v", got, err)
			}
			if mode == "missing-host" && len(got.Servers) != 1 {
				t.Fatalf("good server lost: %+v", got.Servers)
			}
			if mode == "lds" && (!errors.Is(err, ErrUnsupportedDirectory) || len(f.queries) != 0) {
				t.Fatalf("LDS topology was invented: %v", err)
			}
		})
	}
}

func TestReplicationServerSelectionValidatesBeforeIO(t *testing.T) {
	dial := func(context.Context, Config) (*Client, error) {
		t.Fatal("server resolution must not connect")
		return nil, nil
	}
	config := Config{Endpoint: Endpoint{Host: "dc1.example.test"}}
	got, err := resolveReplicationTargets(context.Background(), config, ReplicationSelection{Servers: []Endpoint{{Host: "dc2.example.test"}, {Host: "DC2.example.test"}, {Host: "lds.example.test", Port: 50000}}}, dial)
	if err != nil || !got.Complete || len(got.Servers) != 2 || got.Servers[0].Port != 389 || got.Servers[1].Port != 50000 {
		t.Fatalf("servers=%+v err=%v", got, err)
	}
	for _, selection := range []ReplicationSelection{{Scope: 99}, {Scope: ReplicationScopeSite}, {Scope: ReplicationScopeForest, Servers: []Endpoint{{Host: "dc2.example.test"}}}, {Servers: []Endpoint{{Host: "https://user:password@dc.example.test"}}}} {
		if _, err := resolveReplicationTargets(context.Background(), config, selection, dial); err == nil {
			t.Fatalf("accepted invalid selection %+v", selection)
		}
	}
}
