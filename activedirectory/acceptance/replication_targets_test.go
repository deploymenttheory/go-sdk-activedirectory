package acceptance

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestReplicationScopeExpansion(t *testing.T) {
	for _, selection := range []admodel.ReplicationSelection{{Scope: admodel.ReplicationScopeDomain}, {Scope: admodel.ReplicationScopeDomain, DomainDNS: "example.test"}, {Scope: admodel.ReplicationScopeForest, ForestDNS: "example.test"}, {Scope: admodel.ReplicationScopeSite, SiteName: "London, UK"}} {
		f := InternalNewTopologyFixture()
		config := admodel.Config{
			Endpoint:  admodel.Endpoint{Host: "dc1.example.test", Port: 1636},
			Transport: admodel.TransportLDAPS,
		}
		got, err := adengine.InternalResolveReplicationTargets(
			context.Background(),
			config,
			selection,
			func(context.Context, admodel.Config) (*adengine.Client, error) {
				return f.InternalClient(time.Second), nil
			},
		)
		if err != nil || !got.Complete || len(got.Servers) != 2 {
			t.Fatalf("scope %v: %+v err=%v", selection, got, err)
		}
		for _, endpoint := range got.Servers {
			if endpoint.Port != 636 {
				t.Fatalf("custom anchor port leaked into topology: %+v", endpoint)
			}
		}
		found := false
		for _, query := range f.InternalQueries {
			if query.Scope != admodel.ScopeSubtree {
				continue
			}
			found = true
			if strings.Contains(
				query.Filter,
				"msDS-HasDomainNCs=",
			) != (selection.Scope == admodel.ReplicationScopeDomain) {
				t.Fatalf("scope %v filter %s", selection.Scope, query.Filter)
			}
			if selection.Scope == admodel.ReplicationScopeSite &&
				query.Base != "CN=Servers,"+InternalTopSite {
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
			f := InternalNewTopologyFixture()
			selection := admodel.ReplicationSelection{Scope: admodel.ReplicationScopeForest}
			sentinel := errors.New("injected topology failure")
			switch mode {
			case "partial":
				f.InternalPageFailureBase = InternalTopSites
				f.InternalPageFailure = sentinel
			case "lds":
				f.InternalRoot["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
			case "missing-host":
				delete(f.InternalObjects[InternalTopServerRO].Attributes, "dnshostname")
			case "wrong-forest":
				selection.ForestDNS = "different.test"
			}
			got, err := adengine.InternalResolveReplicationTargets(
				context.Background(),
				admodel.Config{Endpoint: admodel.Endpoint{Host: "dc1.example.test"}},
				selection,
				func(context.Context, admodel.Config) (*adengine.Client, error) {
					return f.InternalClient(time.Second), nil
				},
			)
			if err == nil || got.Complete {
				t.Fatalf("unreported uncertainty: %+v, %v", got, err)
			}
			if mode == "partial" && (len(got.Servers) != 2 || !errors.Is(err, sentinel)) {
				t.Fatalf("partial result lost: %+v, %v", got, err)
			}
			if mode == "missing-host" && len(got.Servers) != 1 {
				t.Fatalf("good server lost: %+v", got.Servers)
			}
			if mode == "lds" &&
				(!errors.Is(err, admodel.ErrUnsupportedDirectory) || len(f.InternalQueries) != 0) {
				t.Fatalf("LDS topology was invented: %v", err)
			}
		})
	}
}

func TestReplicationServerSelectionValidatesBeforeIO(t *testing.T) {
	dial := func(context.Context, admodel.Config) (*adengine.Client, error) {
		t.Fatal("server resolution must not connect")
		return nil, nil
	}
	config := admodel.Config{Endpoint: admodel.Endpoint{Host: "dc1.example.test"}}
	got, err := adengine.InternalResolveReplicationTargets(
		context.Background(),
		config,
		admodel.ReplicationSelection{
			Servers: []admodel.Endpoint{
				{Host: "dc2.example.test"},
				{Host: "DC2.example.test"},
				{Host: "lds.example.test", Port: 50000},
			},
		},
		dial,
	)
	if err != nil || !got.Complete || len(got.Servers) != 2 || got.Servers[0].Port != 389 ||
		got.Servers[1].Port != 50000 {
		t.Fatalf("servers=%+v err=%v", got, err)
	}
	for _, selection := range []admodel.ReplicationSelection{{Scope: 99}, {Scope: admodel.ReplicationScopeSite}, {Scope: admodel.ReplicationScopeForest, Servers: []admodel.Endpoint{{Host: "dc2.example.test"}}}, {Servers: []admodel.Endpoint{{Host: "https://user:password@dc.example.test"}}}} {
		if _, err := adengine.InternalResolveReplicationTargets(
			context.Background(),
			config,
			selection,
			dial,
		); err == nil {
			t.Fatalf("accepted invalid selection %+v", selection)
		}
	}
}
