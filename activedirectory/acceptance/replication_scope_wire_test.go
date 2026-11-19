package acceptance

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

const (
	replicationScopePeer   = "peer.ad.sdk.test"
	replicationScopeSite   = "CN=Site,CN=Sites,CN=Configuration,DC=ad,DC=sdk,DC=test"
	replicationScopePeerDN = "CN=Peer,CN=Servers," + replicationScopeSite
)

func replicationScopeLDAPReply(connection net.Conn, request *ber.Packet) error {
	if len(request.Children) < 2 {
		return errors.New("missing scope LDAP request")
	}
	if request.Children[1].Tag == ldap.ApplicationUnbindRequest {
		return io.EOF
	}
	if request.Children[1].Tag != ldap.ApplicationSearchRequest || len(request.Children[1].Children) != 8 {
		return errors.New("non-read scope LDAP request")
	}
	query := request.Children[1]
	base := query.Children[0].Data.String()
	scope, ok := query.Children[1].Value.(int64)
	if !ok {
		return errors.New("invalid scope LDAP search")
	}
	objects := map[string]map[string][][]byte{}
	switch base {
	case "":
		if scope != 0 {
			return errors.New("RootDSE scope changed")
		}
		objects[""] = map[string][][]byte{
			"supportedcapabilities": {[]byte(admodel.CapabilityActiveDirectory)},
			"defaultnamingcontext":  {[]byte("DC=ad,DC=sdk,DC=test")}, "rootdomainnamingcontext": {[]byte("DC=ad,DC=sdk,DC=test")},
			"configurationnamingcontext": {[]byte("CN=Configuration,DC=ad,DC=sdk,DC=test")},
		}
	case "CN=Partitions,CN=Configuration,DC=ad,DC=sdk,DC=test":
		if scope != 1 {
			return errors.New("crossRef scope changed")
		}
		objects["CN=AD,"+base] = map[string][][]byte{"ncname": {[]byte("DC=ad,DC=sdk,DC=test")}, "dnsroot": {[]byte("ad.sdk.test")}, "systemflags": {[]byte("3")}}
	case "CN=Sites,CN=Configuration,DC=ad,DC=sdk,DC=test":
		if scope == 1 {
			objects[replicationScopeSite] = map[string][][]byte{"name": {[]byte("Site")}}
		} else if scope == 2 {
			objects["CN=NTDS Settings,"+replicationServerDN] = map[string][][]byte{}
			objects["CN=NTDS Settings,"+replicationScopePeerDN] = map[string][][]byte{}
		} else {
			return errors.New("topology search scope changed")
		}
	case "CN=Servers," + replicationScopeSite:
		if scope != 2 {
			return errors.New("site topology scope changed")
		}
		objects["CN=NTDS Settings,"+replicationServerDN] = map[string][][]byte{}
		objects["CN=NTDS Settings,"+replicationScopePeerDN] = map[string][][]byte{}
	case replicationServerDN, replicationScopePeerDN:
		if scope != 0 {
			return errors.New("server lookup scope changed")
		}
		host := portableTLSHost
		if base == replicationScopePeerDN {
			host = replicationScopePeer
		}
		objects[base] = map[string][][]byte{"dnshostname": {[]byte(host)}}
	default:
		return errors.New("scope expansion contacted an unselected directory location")
	}
	// Return stable order independently of map iteration.
	for _, dn := range []string{"", "CN=AD,CN=Partitions,CN=Configuration,DC=ad,DC=sdk,DC=test", replicationScopeSite, "CN=NTDS Settings," + replicationServerDN, "CN=NTDS Settings," + replicationScopePeerDN, replicationServerDN, replicationScopePeerDN} {
		attrs, exists := objects[dn]
		if !exists {
			continue
		}
		entry := portableLDAPEntry(request, attrs)
		protocol := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
		protocol.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
		protocol.AppendChild(entry.Children[1].Children[1])
		if _, err := connection.Write(portableLDAPEnvelope(request, protocol).Bytes()); err != nil {
			return err
		}
	}
	_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{}).Bytes())
	return err
}

func TestPortableReplicationDiscoveredScopesApplyEachExplicitPeerPrincipal(t *testing.T) {
	for _, scope := range []admodel.ReplicationScope{admodel.ReplicationScopeDomain, admodel.ReplicationScopeForest, admodel.ReplicationScopeSite} {
		t.Run(fmt.Sprintf("scope%d", scope), func(t *testing.T) {
			certificate, roots := portableKerberosTLSCertificate(t)
			kdc := newPortableKerberosKDC(t)
			acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
			steps := []portableLDAPStep{acceptor.authenticate, acceptor.offer, acceptor.accept}
			for range 16 {
				steps = append(steps, replicationScopeLDAPReply)
			}
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			dialer := &replicationWireDialer{ldap: wire, kdc: kdc}
			config := portableTLSConfig(admodel.TransportLDAPS, roots)
			config.Endpoint.Port = 1636
			config.Authentication = admodel.AuthenticationKerberos
			config.Credentials = nil
			config.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
			selection := admodel.ReplicationSelection{Scope: scope, ServicePrincipals: map[string]admodel.ReplicationServicePrincipals{
				portableTLSHost: replicationSelectedPrincipals(portableTLSHost), replicationScopePeer: replicationSelectedPrincipals(replicationScopePeer),
			}}
			switch scope {
			case admodel.ReplicationScopeDomain:
				selection.DomainDNS = "ad.sdk.test"
			case admodel.ReplicationScopeForest:
				selection.ForestDNS = "ad.sdk.test"
			case admodel.ReplicationScopeSite:
				selection.SiteName = "Site"
			}
			calls := 0
			result, err := adengine.InternalResolveReplicationTargets(t.Context(), config, selection, func(ctx context.Context, selected admodel.Config) (*adengine.Client, error) {
				calls++
				if selected.Endpoint.Host != portableTLSHost || selected.Kerberos.SPN != "ldap/"+portableTLSHost {
					t.Fatal("anchor auth identity changed")
				}
				session, dialErr := adengine.InternalDialPortableWithDial(ctx, selected, dialer)
				if dialErr != nil {
					return nil, dialErr
				}
				return adengine.InternalNewClient(selected, session), nil
			})
			if err != nil || !result.Complete || !result.Observation.Complete || len(result.Servers) != 2 {
				t.Fatalf("authenticated scope dropped an explicitly mapped peer: servers=%v complete=%v err=%v", result.Servers, result.Complete, err)
			}
			for i, host := range []string{portableTLSHost, replicationScopePeer} {
				if result.Servers[i].Host != host || result.Servers[i].Port != 636 {
					t.Fatal("topology target or transport-default port changed", result.Servers)
				}
				peer, _, targetErr := admodel.InternalReplicationTargetConfig(config, selection, result.Servers[i], true)
				if targetErr != nil || peer.Kerberos.SPN != "ldap/"+host || peer.Validate() != nil {
					t.Fatal("per-target identity was not independently usable", targetErr)
				}
			}
			if calls != 1 || wire.attempts.Load() != 1 || kdc.requests.Load() != 3 || config.Kerberos.SPN != "ldap/"+portableTLSHost {
				t.Fatal("scope expansion replayed authentication, contacted a peer, or changed caller credentials")
			}
			wire.wait(t)
		})
	}
}

func TestPortableReplicationExplicitMultipleServersPreserveSelectedPrincipals(t *testing.T) {
	config := kerberosContractConfig(admodel.KerberosKeytabFile)
	config.Kerberos.KeytabPath = "must-not-read-this-fixture.keytab"
	selection := admodel.ReplicationSelection{
		Servers: []admodel.Endpoint{config.Endpoint, {Host: replicationScopePeer}, {Host: strings.ToUpper(replicationScopePeer)}},
		ServicePrincipals: map[string]admodel.ReplicationServicePrincipals{
			config.Endpoint.Host: replicationSelectedPrincipals(config.Endpoint.Host),
			replicationScopePeer: replicationSelectedPrincipals(replicationScopePeer),
		},
	}
	result, err := adengine.InternalResolveReplicationTargets(t.Context(), config, selection, func(context.Context, admodel.Config) (*adengine.Client, error) {
		t.Fatal("explicit target validation made a network call")
		return nil, errors.New("unexpected fixture network")
	})
	if err != nil || !result.Complete || len(result.Servers) != 2 {
		t.Fatal("explicit multi-server selection changed", result, err)
	}
	for _, endpoint := range result.Servers {
		selected, _, e := admodel.InternalReplicationTargetConfig(config, selection, endpoint, true)
		if e != nil || selected.Kerberos.SPN != "ldap/"+strings.ToLower(endpoint.Host) || selected.Validate() != nil {
			t.Fatal("per-server credentials not selected", e)
		}
	}
}

func TestPortableReplicationDiscoveredUnmappedPeerRetainsPreciseRefusalWithoutDial(t *testing.T) {
	certificate, roots := portableKerberosTLSCertificate(t)
	kdc := newPortableKerberosKDC(t)
	acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
	steps := []portableLDAPStep{acceptor.authenticate, acceptor.offer, acceptor.accept}
	for range 16 {
		steps = append(steps, replicationScopeLDAPReply)
	}
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
	dialer := &replicationWireDialer{ldap: wire, kdc: kdc}
	config := portableTLSConfig(admodel.TransportLDAPS, roots)
	config.Endpoint.Port = 1636
	config.Authentication, config.Credentials = admodel.AuthenticationKerberos, nil
	config.Kerberos = portableKerberosSource(t, kdc, admodel.KerberosPassword, false)
	selection := admodel.ReplicationSelection{
		Scope: admodel.ReplicationScopeDomain, DomainDNS: "ad.sdk.test",
		ServicePrincipals: map[string]admodel.ReplicationServicePrincipals{portableTLSHost: replicationSelectedPrincipals(portableTLSHost)},
	}
	sentinel := errors.New("owned selected-anchor read refusal")
	calls := 0
	reader := adengine.InternalReplicationReader{InternalDial: func(ctx context.Context, selected admodel.Config) (*adengine.Client, error) {
		calls++
		if selected.Endpoint.Host != portableTLSHost || selected.Kerberos.SPN != "ldap/"+portableTLSHost {
			t.Fatal("unmapped peer was dialed or anchor SPN replaced")
		}
		if calls != 1 {
			return nil, sentinel
		}
		session, err := adengine.InternalDialPortableWithDial(ctx, selected, dialer)
		if err != nil {
			return nil, err
		}
		return adengine.InternalNewClient(selected, session), nil
	}}
	result, err := adengine.InternalReadReplicationQueue(t.Context(), config, admodel.ReplicationQueueQuery{Selection: selection}, reader)
	if err == nil || !errors.Is(err, sentinel) || !errors.Is(err, admodel.ErrInvalidConfig) || result.Complete || !result.Targets.Complete || len(result.Servers) != 2 ||
		calls != 2 {
		t.Fatalf("unmapped discovered peer lost partial target/refusal evidence: calls%d result%+v err%v", calls, result, err)
	}
	missing := result.Servers[1]
	if missing.Observation.Endpoint.Host != replicationScopePeer || missing.Observation.Endpoint.Port != 636 || missing.State.Available || missing.State.Complete ||
		!errors.Is(missing.State.Error, admodel.ErrInvalidConfig) {
		t.Fatal("unmapped discovered peer became confirmed empty or disappeared", missing)
	}
	if config.Kerberos.SPN != "ldap/"+portableTLSHost || wire.attempts.Load() != 1 || kdc.requests.Load() != 3 {
		t.Fatal("missing peer triggered credential/network fallback")
	}
	wire.wait(t)
}
