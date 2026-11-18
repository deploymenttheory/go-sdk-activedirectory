package acceptance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

const (
	replicationServerDN   = "CN=DC,CN=Servers,CN=Site,CN=Sites,CN=Configuration,DC=ad,DC=sdk,DC=test"
	replicationComputerDN = "CN=DC,OU=Domain Controllers,DC=ad,DC=sdk,DC=test"
)

type replicationWireDialer struct {
	ldap        *portableLDAPWire
	kdc         *portableKerberosKDC
	mapper, drs *replicationRPCFixture
	rpcAttempts atomic.Int32
}

func (d *replicationWireDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || network != "tcp" || host != portableTLSHost {
		return nil, errors.New("selected RPC/LDAP/KDC host was replaced")
	}
	var target string
	switch port {
	case "88":
		target = d.kdc.listener.Addr().String()
	case "135":
		target = d.mapper.listener.Addr().String()
		d.rpcAttempts.Add(1)
	case "49153":
		target = d.drs.listener.Addr().String()
		d.rpcAttempts.Add(1)
	default:
		return d.ldap.DialContext(ctx, network, address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func replicationLDAPIdentityReply(scenario string) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if len(request.Children) < 2 || request.Children[1].Tag != ldap.ApplicationSearchRequest {
			return errors.New("non-read LDAP operation in diagnostic workflow")
		}
		query := request.Children[1]
		dn := query.Children[0].Data.String()
		attributes := map[string][][]byte{}
		guid, _ := admodel.ParseGUID("11111111-2222-3333-4444-555555555555")
		switch dn {
		case "":
			attributes = map[string][][]byte{
				"supportedcapabilities": {[]byte(admodel.CapabilityActiveDirectory)},
				"dnshostname":           {[]byte(portableTLSHost)}, "dsservicename": {[]byte("CN=NTDS Settings," + replicationServerDN)},
				"servername": {[]byte(replicationServerDN)}, "rootdomainnamingcontext": {[]byte("DC=ad,DC=sdk,DC=test")},
				"defaultnamingcontext": {[]byte("DC=ad,DC=sdk,DC=test")}, "configurationnamingcontext": {[]byte("CN=Configuration,DC=ad,DC=sdk,DC=test")},
				"msds-replalloutboundneighbors": {[]byte(InternalOutboundXML)},
			}
		case "CN=NTDS Settings," + replicationServerDN:
			attributes["objectguid"] = [][]byte{guid.Bytes()}
			if scenario == "wrong-dsa" {
				attributes["objectguid"][0][0] ^= 1
			}
		case replicationServerDN:
			attributes["serverreference"] = [][]byte{[]byte(replicationComputerDN)}
		case replicationComputerDN:
			attributes["dnshostname"] = [][]byte{[]byte(portableTLSHost)}
			attributes["serviceprincipalname"] = [][]byte{[]byte("ldap/" + portableTLSHost), []byte(replicationRPCPrincipal)}
			if scenario == "unregistered-spn" {
				attributes["serviceprincipalname"] = [][]byte{[]byte("ldap/" + portableTLSHost)}
			}
			if scenario == "range-gap" {
				attributes["serviceprincipalname;range=2-*"] = attributes["serviceprincipalname"]
				delete(attributes, "serviceprincipalname")
			}
		default:
			return errors.New("diagnostic LDAP read escaped expected DSA/computer objects")
		}
		entry := portableLDAPEntry(request, attributes)
		protocol := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
		protocol.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
		protocol.AppendChild(entry.Children[1].Children[1])
		if _, err := connection.Write(portableLDAPEnvelope(request, protocol).Bytes()); err != nil {
			return err
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{}).Bytes())
		return err
	}
}

func replicationRPCReader(
	t *testing.T,
	source admodel.KerberosCredentialSource,
	scenario string,
) (admodel.Config, admodel.ReplicationSelection, adengine.InternalReplicationReader, *replicationWireDialer) {
	t.Helper()
	certificate, roots := portableKerberosTLSCertificate(t)
	kdc := newPortableKerberosKDC(t, func(kdc *portableKerberosKDC) {
		kdc.services[replicationRPCPrincipal] = true
		if err := kdc.keys.AddEntry(replicationRPCPrincipal, portableKerberosRealm, "owned-RPC-stage-fixture-key", time.Now().Add(-time.Hour), 1, 18); err != nil {
			t.Fatal(err)
		}
	})
	acceptor := newPortableKerberosAcceptor(t, kdc, certificate.Leaf)
	steps := []portableLDAPStep{acceptor.authenticate, acceptor.offer, acceptor.accept}
	for range 8 {
		steps = append(steps, replicationLDAPIdentityReply(scenario))
	}
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
	mapper, drs := newReplicationRPCFixture(t, kdc, true, scenario), newReplicationRPCFixture(t, kdc, false, scenario)
	dialer := &replicationWireDialer{ldap: wire, kdc: kdc, mapper: mapper, drs: drs}
	config := portableTLSConfig(admodel.TransportLDAPS, roots)
	config.Authentication, config.Credentials = admodel.AuthenticationKerberos, nil
	config.Kerberos = portableKerberosSource(t, kdc, source, false)
	principals := replicationSelectedPrincipals(portableTLSHost)
	selection := admodel.ReplicationSelection{ServicePrincipals: map[string]admodel.ReplicationServicePrincipals{portableTLSHost: principals}}
	reader := adengine.InternalReplicationReader{
		InternalDial: func(ctx context.Context, config admodel.Config) (*adengine.Client, error) {
			session, err := adengine.InternalDialPortableWithDial(ctx, config, dialer)
			if err != nil {
				return nil, err
			}
			return adengine.InternalNewClient(config, session), nil
		},
		InternalNative: func(ctx context.Context, config admodel.Config, root admodel.RootDSE, instance []byte, request admodel.InternalReplicationRequest) (map[admodel.InternalReplicationInfo]admodel.InternalReplicationNativeReply, error) {
			return adengine.InternalReadReplicationPortableWithDial(ctx, config, root, instance, request, dialer)
		},
	}
	return config, selection, reader, dialer
}

func replicationRPCWait(t *testing.T, dialer *replicationWireDialer) {
	t.Helper()
	dialer.ldap.wait(t)
	dialer.mapper.wait(t)
	dialer.drs.wait(t)
}

func TestPortableReplicationAuthenticatedPublicWorkflowAllSourcesAndCategories(t *testing.T) {
	for _, source := range []admodel.KerberosCredentialSource{admodel.KerberosPassword, admodel.KerberosKeytabFile, admodel.KerberosCredentialCacheFile} {
		for _, operation := range []string{"partners", "failures", "queue"} {
			t.Run(fmt.Sprintf("source%d/%s", source, operation), func(t *testing.T) {
				config, selection, reader, dialer := replicationRPCReader(t, source, "valid")
				originalCredential := replicationCredentialFileDigest(t, config)
				var protection []admodel.ReplicationRPCProtection
				switch operation {
				case "partners":
					result, err := adengine.InternalReadReplicationPartners(
						t.Context(),
						config,
						admodel.ReplicationPartnerQuery{Selection: selection, Direction: admodel.ReplicationBoth},
						reader,
					)
					if err != nil || !result.Complete || len(result.Servers) != 1 || !result.Servers[0].Inbound.Complete || !result.Servers[0].Outbound.Complete ||
						len(result.Servers[0].Partners) != 2 {
						t.Fatalf("actual protected partner workflow incomplete: %v", err)
					}
					inbound, outbound := result.Servers[0].Partners[0], result.Servers[0].Partners[1]
					protection = result.Servers[0].Observation.RPCProtection
					if inbound.LastObjectUSN == nil || *inbound.LastObjectUSN != -9 || inbound.ReplicaFlags == nil || *inbound.ReplicaFlags != 0x80000001 ||
						outbound.Direction != admodel.ReplicationOutbound ||
						outbound.LastObjectUSN != nil {
						t.Fatal("native-equivalent fields or outbound direction changed")
					}
				case "failures":
					result, err := adengine.InternalReadReplicationFailures(t.Context(), config, admodel.ReplicationFailureQuery{Selection: selection}, reader)
					if err != nil || !result.Complete || len(result.Servers) != 1 || len(result.Servers[0].Failures) != 2 || !result.Servers[0].Connections.Complete ||
						!result.Servers[0].Links.Complete {
						t.Fatalf("actual protected failure workflow incomplete: %v", err)
					}
					if result.Servers[0].Failures[0].LastResult != 8453 || result.Servers[0].Failures[1].Kind != admodel.ReplicationLinkFailure {
						t.Fatal("record status became operation refusal or failure kinds collapsed")
					}
					protection = result.Servers[0].Observation.RPCProtection
				case "queue":
					result, err := adengine.InternalReadReplicationQueue(t.Context(), config, admodel.ReplicationQueueQuery{Selection: selection}, reader)
					if err != nil || !result.Complete || len(result.Servers) != 1 || len(result.Servers[0].Operations) != 2 || result.Servers[0].Operations[0].SerialNumber != 22 ||
						result.Servers[0].Operations[1].SerialNumber != 21 ||
						result.Servers[0].Operations[0].Type != 65535 {
						t.Fatalf("actual protected queue workflow incomplete: %v", err)
					}
					protection = result.Servers[0].Observation.RPCProtection
				}
				if len(protection) != 2 {
					t.Fatal("per-stage RPC observations missing")
				}
				for i, observed := range protection {
					if observed.Endpoint.Host != portableTLSHost || observed.Realm != portableKerberosRealm || observed.EncryptionType != 18 || observed.CipherBits != 256 ||
						!observed.MutualAuthentication || !observed.HeaderSigned || !observed.Confidential || !observed.Complete || observed.ExpiresAt.IsZero() {
						t.Fatal("requested protection was substituted for measured RPC facts")
					}
					if i == 0 && (observed.Stage != "endpoint-map" || observed.Endpoint.Port != 135 || observed.ServicePrincipal != replicationRPCPrincipal) ||
						i == 1 && (observed.Stage != "drs" || observed.Endpoint.Port != 49153 || observed.ServicePrincipal != "ldap/"+portableTLSHost) {
						t.Fatal("RPC stage identity or selected endpoint changed")
					}
				}
				if dialer.rpcAttempts.Load() != 2 || dialer.mapper.requests.Load() != 1 {
					t.Fatal("RPC endpoint selection retried or followed advertised foreign IP")
				}
				wantKDC := int32(9)
				if source == admodel.KerberosCredentialCacheFile {
					wantKDC = 3
				}
				if dialer.kdc.requests.Load() != wantKDC {
					t.Fatalf("stage credential reuse/fallback: KDC requests%d expected%d", dialer.kdc.requests.Load(), wantKDC)
				}
				if config.Kerberos.SPN != "ldap/"+portableTLSHost {
					t.Fatal("shared caller SPN changed")
				}
				if replicationCredentialFileDigest(t, config) != originalCredential {
					t.Fatal("caller-owned credential file changed")
				}
				replicationRPCWait(t, dialer)
			})
		}
	}
}

func TestPortableReplicationAuthenticatedFailureIsolationAndRetirement(t *testing.T) {
	for _, scenario := range []string{"refusal", "malformed", "tampered", "lost", "cancel", "fault"} {
		t.Run(scenario, func(t *testing.T) {
			config, selection, reader, dialer := replicationRPCReader(t, admodel.KerberosPassword, scenario)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if scenario == "cancel" {
				go func() {
					select {
					case <-dialer.drs.started:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			result, err := adengine.InternalReadReplicationFailures(ctx, config, admodel.ReplicationFailureQuery{Selection: selection}, reader)
			if err == nil || result.Complete || len(result.Servers) != 1 {
				t.Fatalf("failed wire became healthy: %+v %v", result, err)
			}
			server := result.Servers[0]
			if len(server.Observation.RPCProtection) != 2 || !server.Observation.RPCProtection[0].Complete || !server.Observation.RPCProtection[1].MutualAuthentication ||
				server.Observation.RPCProtection[1].Complete != (scenario == "refusal") {
				t.Fatal("failed query discarded partial protection facts or asserted a healthy context")
			}
			var status *admodel.NativeStatusError
			if scenario == "refusal" {
				if !errors.As(server.Connections.Error, &status) || status.Code != 8453 || !errors.Is(err, replication.ErrReplicationPermission) || !server.Links.Complete ||
					len(server.Failures) != 1 {
					t.Fatalf("actual category refusal lost/borrowed: %v", err)
				}
			} else {
				if scenario == "fault" {
					if !errors.As(server.Connections.Error, &status) || status.Code != 5 || admodel.Classify(err) != admodel.ClassDenied {
						t.Fatalf("verified RPC fault lost its actual denial status/class: %v", err)
					}
				} else if scenario != "malformed" && admodel.Classify(err) != admodel.ClassTransport {
					t.Fatalf("transport failure became a fabricated result/status class: %v", err)
				}
				if errors.As(server.Links.Error, &status) || server.Links.Complete || server.Links.Available || !errors.Is(server.Links.Error, admodel.ErrIncompleteResult) {
					t.Fatal("unattempted category borrowed prior status or became empty")
				}
				if scenario == "malformed" && (len(server.Failures) != 1 || !server.Connections.Available) {
					t.Fatal("valid malformed-array prefix lost")
				}
				if scenario != "malformed" && server.Connections.Available {
					t.Fatal("unverified bytes published")
				}
				if scenario == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatal("caller cancellation cause lost")
				}
				if dialer.drs.requests.Load() != 2 {
					t.Fatal("damaged association retried or attempted sibling/unbind")
				}
			}
			replicationRPCWait(t, dialer)
		})
	}
}

func TestPortableReplicationLDAPIdentityMismatchPreventsRPCAndKDCStageAccess(t *testing.T) {
	for _, scenario := range []string{"wrong-dsa", "unregistered-spn", "range-gap"} {
		t.Run(scenario, func(t *testing.T) {
			config, selection, reader, dialer := replicationRPCReader(t, admodel.KerberosPassword, scenario)
			result, err := adengine.InternalReadReplicationQueue(t.Context(), config, admodel.ReplicationQueueQuery{Selection: selection}, reader)
			if err == nil || result.Complete || dialer.rpcAttempts.Load() != 0 || dialer.kdc.requests.Load() != 3 {
				t.Fatalf("unbound directory identity crossed RPC gate: attempts%d KDC%d %v", dialer.rpcAttempts.Load(), dialer.kdc.requests.Load(), err)
			}
			replicationRPCWait(t, dialer)
		})
	}
}
