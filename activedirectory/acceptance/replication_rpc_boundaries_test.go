package acceptance

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableReplicationEndpointMapFailureNeverDialsDRSOrBorrowsAStatus(t *testing.T) {
	for _, scenario := range []string{"epm-refusal", "epm-empty", "epm-malformed", "epm-tampered"} {
		t.Run(scenario, func(t *testing.T) {
			config, selection, reader, dialer := replicationRPCReader(t, admodel.KerberosPassword, scenario)
			result, err := adengine.InternalReadReplicationFailures(t.Context(), config, admodel.ReplicationFailureQuery{Selection: selection}, reader)
			if err == nil || result.Complete || len(result.Servers) != 1 || dialer.rpcAttempts.Load() != 1 || dialer.kdc.requests.Load() != 6 || dialer.drs.requests.Load() != 0 {
				t.Fatalf("failed endpoint map crossed the DRS boundary: %v", err)
			}
			server := result.Servers[0]
			var status *admodel.NativeStatusError
			if scenario == "epm-refusal" {
				if !errors.As(err, &status) || status.Operation != "ept_map" || status.Code != 1753 {
					t.Fatal("actual endpoint-map status lost")
				}
			} else if errors.As(err, &status) {
				t.Fatal("local endpoint-map failure manufactured a server status")
			}
			for _, category := range []admodel.ReplicationQueryState{server.Connections, server.Links} {
				if category.Available || category.Complete || !errors.Is(category.Error, admodel.ErrIncompleteResult) || errors.As(category.Error, &status) {
					t.Fatal("unsubmitted DRS category borrowed endpoint-map data or status")
				}
			}
			if scenario == "epm-malformed" && !errors.Is(err, admodel.ErrInvalidResult) || scenario == "epm-empty" && admodel.Classify(err) != admodel.ClassUnsupported ||
				scenario == "epm-tampered" && admodel.Classify(err) != admodel.ClassTransport {
				t.Fatal("endpoint-map failure classification changed")
			}
			replicationRPCWait(t, dialer)
		})
	}
}

func TestPortableReplicationAuthenticatedZeroCountsAreConfirmedEmpty(t *testing.T) {
	config, selection, reader, dialer := replicationRPCReader(t, admodel.KerberosPassword, "empty")
	result, err := adengine.InternalReadReplicationFailures(t.Context(), config, admodel.ReplicationFailureQuery{Selection: selection}, reader)
	if err != nil || !result.Complete || len(result.Servers) != 1 {
		t.Fatalf("authenticated empty failure containers became missing: %v", err)
	}
	server := result.Servers[0]
	if !server.Connections.Available || !server.Connections.Complete || !server.Links.Available || !server.Links.Complete || len(server.Failures) != 0 {
		t.Fatal("actual zero counts were not preserved")
	}
	replicationRPCWait(t, dialer)
}

func replicationCredentialFileDigest(t *testing.T, config admodel.Config) [32]byte {
	t.Helper()
	path := config.Kerberos.KeytabPath
	if path == "" {
		path = config.Kerberos.CachePath
	}
	if path == "" {
		return [32]byte{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot hash caller-owned credential source")
	}
	defer clear(data)
	return sha256.Sum256(data)
}

func TestPortableReplicationRPCFailureRetainsIndependentLDAPOutboundObservation(t *testing.T) {
	config, selection, reader, dialer := replicationRPCReader(t, admodel.KerberosPassword, "tampered")
	result, err := adengine.InternalReadReplicationPartners(t.Context(), config, admodel.ReplicationPartnerQuery{Selection: selection, Direction: admodel.ReplicationBoth}, reader)
	if err == nil || result.Complete || len(result.Servers) != 1 {
		t.Fatalf("tampered RPC became healthy: %v", err)
	}
	server := result.Servers[0]
	if server.Inbound.Complete || server.Inbound.Available || !server.Outbound.Complete || !server.Outbound.Available || len(server.Partners) != 1 ||
		server.Partners[0].Direction != admodel.ReplicationOutbound || len(server.OutboundObjects) != 1 {
		t.Fatal("RPC failure discarded or reinterpreted the independent LDAP observation")
	}
	replicationRPCWait(t, dialer)
}

type replicationRejectDialer struct{ calls int }

func (d *replicationRejectDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls++
	return nil, errors.New("unexpected test dial")
}

func TestPortableReplicationRPCValidatesIdentityAndKindsBeforeCredentialLoading(t *testing.T) {
	for _, scenario := range []string{"missing-selection", "missing-identity", "wrong-instance", "wrong-forest", "unregistered-service", "unsupported-kind", "duplicate-kind"} {
		t.Run(scenario, func(t *testing.T) {
			config := kerberosContractConfig(admodel.KerberosKeytabFile)
			config.Kerberos.KeytabPath = "must-not-load-private-fixture.keytab"
			p := replicationSelectedPrincipals(config.Endpoint.Host)
			guid, _ := admodel.ParseGUID("11111111-2222-3333-4444-555555555555")
			forestDN := "DC=ad,DC=sdk,DC=test"
			root := admodel.RootDSE{DNSHostName: &config.Endpoint.Host, RootDomainNamingContext: &forestDN, SupportedCapabilities: []string{admodel.CapabilityActiveDirectory}}
			identity := admodel.InternalReplicationServiceIdentity{DSA: guid, ForestDNS: "ad.sdk.test", RegisteredSPNs: []string{p.LDAP, p.EndpointMapper}}
			request := admodel.InternalReplicationRequest{
				InternalKinds:             []admodel.InternalReplicationInfo{admodel.InternalReplicationNeighbors},
				InternalServicePrincipals: &p,
				InternalPortableIdentity:  &identity,
			}
			instance := guid.Bytes()
			switch scenario {
			case "missing-selection":
				request.InternalServicePrincipals = nil
			case "missing-identity":
				request.InternalPortableIdentity = nil
			case "wrong-instance":
				instance[0] ^= 1
			case "wrong-forest":
				identity.ForestDNS = "foreign.test"
			case "unregistered-service":
				identity.RegisteredSPNs = []string{p.LDAP}
			case "unsupported-kind":
				request.InternalKinds = []admodel.InternalReplicationInfo{1}
			case "duplicate-kind":
				request.InternalKinds = append(request.InternalKinds, request.InternalKinds[0])
			}
			dialer := &replicationRejectDialer{}
			_, err := adengine.InternalReadReplicationPortableWithDial(t.Context(), config, root, instance, request, dialer)
			if err == nil || dialer.calls != 0 || errors.Is(err, admodel.ErrKerberosAuthentication) {
				t.Fatalf("invalid context crossed credential/network boundary: calls%d %v", dialer.calls, err)
			}
		})
	}
}
