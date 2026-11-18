package acceptance

import (
	"context"
	"errors"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

func replicationSelectedPrincipals(host string) replication.ReplicationServicePrincipals {
	return replication.ReplicationServicePrincipals{LDAP: "ldap/" + host, DRS: "ldap/" + host, EndpointMapper: "RPC/11111111-2222-3333-4444-555555555555._msdcs.ad.sdk.test"}
}

func TestPortableReplicationPrincipalsAreValidatedBeforeCredentialsOrNetwork(t *testing.T) {
	for _, scenario := range []string{"bad-key", "ambiguous-case-key", "wrong-LDAP-host", "wrong-DRS-host", "missing-guid", "wrong-service", "anchor-disagreement", "native-map"} {
		t.Run(scenario, func(t *testing.T) {
			config := kerberosContractConfig(admodel.KerberosKeytabFile)
			config.Kerberos.KeytabPath = "must-not-read-this-caller-path"
			p := replicationSelectedPrincipals(config.Endpoint.Host)
			selection := admodel.ReplicationSelection{ServicePrincipals: map[string]admodel.ReplicationServicePrincipals{config.Endpoint.Host: p}}
			switch scenario {
			case "bad-key":
				selection.ServicePrincipals["https://user:secret@bad/"] = p
			case "ambiguous-case-key":
				selection.ServicePrincipals[strings.ToUpper(config.Endpoint.Host)+"."] = p
			case "wrong-LDAP-host":
				p.LDAP = "ldap/other.example.test"
			case "wrong-DRS-host":
				p.DRS = "ldap/other.example.test"
			case "missing-guid":
				p.EndpointMapper = "RPC/dc.example.test"
			case "wrong-service":
				p.EndpointMapper = "HOST/11111111-2222-3333-4444-555555555555._msdcs.ad.sdk.test"
			case "anchor-disagreement":
				p.LDAP = "ldap/" + strings.ToUpper(config.Endpoint.Host)
			case "native-map":
				config.Backend = admodel.BackendNative
			}
			selection.ServicePrincipals[config.Endpoint.Host] = p
			calls := 0
			_, err := adengine.InternalResolveReplicationTargets(context.Background(), config, selection, func(context.Context, admodel.Config) (*adengine.Client, error) {
				calls++
				return nil, errors.New("unexpected network")
			})
			if err == nil || calls != 0 {
				t.Fatalf("invalid identity selection crossed the preflight boundary: calls%d %v", calls, err)
			}
		})
	}
}

func TestPortableReplicationMissingPeerIdentityPreservesOtherServerAttempt(t *testing.T) {
	config := kerberosContractConfig(admodel.KerberosKeytabFile)
	config.Kerberos.KeytabPath = "caller-private-path-never-opened-by-this-fixture"
	originalSPN := config.Kerberos.SPN
	good := "peer.example.test"
	selection := admodel.ReplicationSelection{
		Servers:           []admodel.Endpoint{{Host: "unmapped.example.test"}, {Host: good}},
		ServicePrincipals: map[string]admodel.ReplicationServicePrincipals{good: replicationSelectedPrincipals(good)},
	}
	calls := 0
	sentinel := errors.New("selected peer test dial")
	reader := adengine.InternalReplicationReader{InternalDial: func(_ context.Context, selected admodel.Config) (*adengine.Client, error) {
		calls++
		if selected.Endpoint.Host != good || selected.Kerberos.SPN != "ldap/"+good {
			t.Fatal("anchor identity was reused for peer")
		}
		return nil, sentinel
	}}
	result, err := adengine.InternalReadReplicationQueue(context.Background(), config, admodel.ReplicationQueueQuery{Selection: selection}, reader)
	if err == nil || !errors.Is(err, sentinel) || calls != 1 || len(result.Servers) != 2 || !result.Targets.Complete || result.Complete {
		t.Fatalf("missing identity lost partial target results: calls%d %+v %v", calls, result, err)
	}
	if !errors.Is(result.Servers[0].State.Error, admodel.ErrInvalidConfig) || result.Servers[0].State.Available || result.Servers[0].State.Complete {
		t.Fatal("missing identity became confirmed empty")
	}
	if config.Kerberos.SPN != originalSPN {
		t.Fatal("per-target selection mutated caller credentials")
	}
}

func TestPortableReplicationSelectionCopiesCallerMap(t *testing.T) {
	config := kerberosContractConfig(admodel.KerberosPassword)
	p := replicationSelectedPrincipals(config.Endpoint.Host)
	selection := admodel.ReplicationSelection{ServicePrincipals: map[string]admodel.ReplicationServicePrincipals{config.Endpoint.Host: p}}
	result, err := replication.ResolveReplicationTargets(context.Background(), config, selection)
	if err != nil || !result.Complete {
		t.Fatal(result, err)
	}
	delete(selection.ServicePrincipals, config.Endpoint.Host)
	if len(result.Requested.ServicePrincipals) != 1 {
		t.Fatal("result retained the caller's mutable identity map")
	}
}
