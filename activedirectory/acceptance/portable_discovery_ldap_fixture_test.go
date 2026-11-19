package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type portableDiscoveryLDAPFixture struct {
	topology *InternalTopologyFixture
	scenario string
	mu       sync.Mutex
	queries  []string
	stalled  chan struct{}
}

func portableDiscoveryTopology(scenario string) *portableDiscoveryLDAPFixture {
	topology := InternalNewTopologyFixture()
	topology.InternalRoot["dnshostname"] = [][]byte{[]byte(portableTLSHost)}
	classes := map[string]string{
		InternalTopDomain:                   "domainDNS",
		InternalTopServer:                   "server",
		InternalTopServerRO:                 "server",
		InternalTopDSA:                      "nTDSDSA",
		InternalTopDSARO:                    "nTDSDSA",
		InternalTopComputer:                 "computer",
		InternalTopComputerRO:               "computer",
		InternalTopCrossRef:                 "crossRef",
		"CN=CHILD," + InternalTopPartitions: "crossRef",
		"CN=APP," + InternalTopPartitions:   "crossRef",
		"CN=EXT," + InternalTopPartitions:   "crossRef",
		InternalTopPartitions:               "crossRefContainer",
		InternalTopSchema:                   "dMD",
		InternalTopRID:                      "rIDManager",
		InternalTopInfrastructure:           "infrastructureUpdate",
		InternalTopCategory:                 "classSchema",
		InternalTopCategoryRO:               "classSchema",
		InternalTopSite:                     "site",
		InternalTopTrust:                    "trustedDomain",
	}
	for dn, class := range classes {
		topology.InternalObjects[dn].Attributes["objectclass"] = [][]byte{[]byte("top"), []byte(class)}
	}
	domainSID, _ := admodel.ParseSID("S-1-5-21-101-202-303")
	topology.InternalObjects[InternalTopDomain].Attributes["objectsid"] = [][]byte{domainSID.Bytes()}
	for index, dn := range []string{InternalTopComputer, InternalTopComputerRO} {
		computerSID, _ := admodel.ParseSID(fmt.Sprintf("S-1-5-21-101-202-303-%d", 1001+index))
		topology.InternalObjects[dn].Attributes["objectsid"] = [][]byte{computerSID.Bytes()}
		topology.InternalObjects[dn].Attributes["objectguid"] = [][]byte{bytes.Repeat([]byte{byte(10 + index)}, 16)}
		host := portableTLSHost
		if index != 0 {
			host = "dc2.example.test"
		}
		topology.InternalObjects[dn].Attributes["dnshostname"] = [][]byte{[]byte(host)}
	}
	topology.InternalObjects[InternalTopServer].Attributes["dnshostname"] = [][]byte{[]byte(portableTLSHost)}
	switch scenario {
	case "wrong-domain":
		topology.InternalRoot["defaultnamingcontext"] = [][]byte{[]byte("DC=wrong,DC=test")}
	case "wrong-root-host":
		topology.InternalRoot["dnshostname"] = [][]byte{[]byte("other.example.test")}
	case "wrong-dsa-parent":
		topology.InternalRoot["dsservicename"] = [][]byte{[]byte(InternalTopDSARO)}
	case "missing-domain-sid":
		delete(topology.InternalObjects[InternalTopDomain].Attributes, "objectsid")
	case "wrong-crossref-domain":
		topology.InternalObjects[InternalTopCrossRef].Attributes["dnsroot"] = [][]byte{[]byte("wrong.test")}
	case "external-crossref":
		topology.InternalObjects[InternalTopCrossRef].Attributes["systemflags"] = [][]byte{[]byte("0")}
	case "disabled-crossref":
		topology.InternalObjects[InternalTopCrossRef].Attributes["enabled"] = [][]byte{[]byte("FALSE")}
	case "wrong-computer-host":
		topology.InternalObjects[InternalTopComputer].Attributes["dnshostname"] = [][]byte{[]byte("other.example.test")}
	case "foreign-computer-reference":
		topology.InternalObjects[InternalTopServer].Attributes["serverreference"] = [][]byte{[]byte("CN=Foreign,DC=foreign,DC=test")}
	case "wrong-computer-sid":
		sid, _ := admodel.ParseSID("S-1-5-21-404-505-606-1001")
		topology.InternalObjects[InternalTopComputer].Attributes["objectsid"] = [][]byte{sid.Bytes()}
	case "wrong-dsa-domain":
		topology.InternalObjects[InternalTopDSA].Attributes["msds-hasdomainncs"] = [][]byte{[]byte("DC=wrong,DC=test")}
	}
	return &portableDiscoveryLDAPFixture{topology: topology, scenario: scenario, stalled: make(chan struct{})}
}

func portableDiscoveryFilter(filter *ber.Packet, attributes map[string][][]byte) bool {
	switch filter.Tag {
	case 0:
		for _, child := range filter.Children {
			if !portableDiscoveryFilter(child, attributes) {
				return false
			}
		}
		return true
	case 1:
		for _, child := range filter.Children {
			if portableDiscoveryFilter(child, attributes) {
				return true
			}
		}
		return false
	case 2:
		return len(filter.Children) == 1 && !portableDiscoveryFilter(filter.Children[0], attributes)
	case 3:
		if len(filter.Children) != 2 {
			return false
		}
		name := strings.ToLower(filter.Children[0].Data.String())
		wanted := filter.Children[1].Data.String()
		for _, value := range attributes[name] {
			if strings.EqualFold(string(value), wanted) {
				return true
			}
		}
	case 7:
		return len(attributes[strings.ToLower(filter.Data.String())]) > 0
	case 9:
		var name, rule, wanted string
		for _, part := range filter.Children {
			switch part.Tag {
			case 1:
				rule = part.Data.String()
			case 2:
				name = strings.ToLower(part.Data.String())
			case 3:
				wanted = part.Data.String()
			}
		}
		if rule != "1.2.840.113556.1.4.803" {
			return false
		}
		mask, err := strconv.ParseUint(wanted, 10, 32)
		if err != nil {
			return false
		}
		for _, value := range attributes[name] {
			actual, err := strconv.ParseUint(string(value), 10, 32)
			if err == nil && actual&mask == mask {
				return true
			}
		}
	}
	return false
}

func portableDiscoveryEntry(request *ber.Packet, object admodel.Object, properties *ber.Packet) *ber.Packet {
	attributes := map[string][][]byte{}
	for name, values := range object.Attributes {
		for _, property := range properties.Children {
			if property.Data.String() == "*" || strings.EqualFold(property.Data.String(), name) {
				attributes[name] = values
				break
			}
		}
	}
	entry := portableLDAPEntry(request, attributes)
	protocol := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
	protocol.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, object.DistinguishedName, ""))
	protocol.AppendChild(entry.Children[1].Children[1])
	return portableLDAPEnvelope(request, protocol)
}

func (f *portableDiscoveryLDAPFixture) read(connection net.Conn, request *ber.Packet) error {
	if len(request.Children) >= 2 && request.Children[1].Tag == ldap.ApplicationUnbindRequest {
		return io.EOF
	}
	if len(request.Children) < 2 || request.Children[1].Tag != ldap.ApplicationSearchRequest || len(request.Children[1].Children) != 8 {
		return errors.New("non-read/malformed LDAP request in discovery")
	}
	query := request.Children[1]
	base := query.Children[0].Data.String()
	scope, ok := query.Children[1].Value.(int64)
	if !ok {
		return errors.New("invalid discovery LDAP scope")
	}
	f.mu.Lock()
	f.queries = append(f.queries, base)
	f.mu.Unlock()
	if base == InternalTopPartitions && (f.scenario == "denied" || f.scenario == "referral") {
		code := int64(50)
		if f.scenario == "referral" {
			code = 10
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, code, &ldap.ControlPaging{}).Bytes())
		return err
	}
	if base == InternalTopPartitions && f.scenario == "lost" {
		return io.EOF
	}
	if base == InternalTopPartitions && f.scenario == "cancel" {
		close(f.stalled)
		var extra [1]byte
		_, err := connection.Read(extra[:])
		return err
	}
	var objects []admodel.Object
	if base == "" {
		objects = []admodel.Object{{Attributes: f.topology.InternalRoot}}
	} else {
		if scope == int64(admodel.ScopeBase) {
			if object, exists := f.topology.InternalObjects[base]; exists {
				objects = append(objects, object)
			}
		} else {
			var candidates []string
			switch base {
			case InternalTopPartitions:
				candidates = []string{InternalTopCrossRef, "CN=CHILD," + InternalTopPartitions, "CN=APP," + InternalTopPartitions, "CN=EXT," + InternalTopPartitions}
			case InternalTopSites:
				if scope == int64(admodel.ScopeOneLevel) {
					candidates = []string{InternalTopSite}
				} else {
					candidates = []string{InternalTopDSA, InternalTopDSARO}
				}
			case "CN=Servers," + InternalTopSite:
				candidates = []string{InternalTopDSA, InternalTopDSARO}
			case InternalTopServer:
				candidates = []string{InternalTopDSA}
			case InternalTopServerRO:
				candidates = []string{InternalTopDSARO}
			case InternalTopSystem:
				candidates = []string{InternalTopTrust}
			default:
				return errors.New("discovery escaped the explicit LDAP topology")
			}
			for _, dn := range candidates {
				objects = append(objects, f.topology.InternalObjects[dn])
			}
		}
		objects = slices.DeleteFunc(objects, func(object admodel.Object) bool {
			return !portableDiscoveryFilter(query.Children[6], object.Attributes)
		})
	}
	if base == InternalTopPartitions && f.scenario == "ambiguous-crossref" && len(objects) == 1 {
		objects = append(objects, objects[0])
	}
	if base == InternalTopDomain && f.scenario == "wrong-returned-domain-dn" && len(objects) == 1 {
		objects[0].DistinguishedName = "DC=other,DC=test"
	}
	if base == InternalTopPartitions && f.scenario == "wrong-crossref-class" && len(objects) == 1 {
		objects[0].Attributes["objectclass"] = [][]byte{[]byte("organizationalUnit")}
	}
	// Stable fixture order makes replica ordering assertions independent of map iteration.
	sort.SliceStable(objects, func(i, j int) bool { return objects[i].DistinguishedName < objects[j].DistinguishedName })
	for _, object := range objects {
		if _, err := connection.Write(portableDiscoveryEntry(request, object, query.Children[7]).Bytes()); err != nil {
			return err
		}
	}
	_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{}).Bytes())
	return err
}

func newPortableDiscoveryLDAP(t *testing.T, scenario string, transport admodel.Transport) (admodel.Config, *portableLDAPWire, *portableDiscoveryLDAPFixture) {
	t.Helper()
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	fixture := portableDiscoveryTopology(scenario)
	steps := []portableLDAPStep{portableLDAPBind(0)}
	for range 128 {
		steps = append(steps, fixture.read)
	}
	wire := newPortableLDAPWire(t, transport, certificate, steps...)
	config := portableTLSConfig(transport, roots)
	config.Timeout = 2 * time.Second
	return config, wire, fixture
}

func portableDiscoveryDialer(wire *portableLDAPWire) func(context.Context, admodel.Config) (*adengine.Client, error) {
	return func(ctx context.Context, config admodel.Config) (*adengine.Client, error) {
		session, err := adengine.InternalDialPortableWithDial(ctx, config, portableDiscoveryPortWire{wire: wire, port: config.Endpoint.Port})
		if err != nil {
			return nil, err
		}
		return adengine.InternalNewClient(config, session), nil
	}
}

// The DNS advertisement and the authenticated transport use separate ports.
// Verify the SDK's requested socket endpoint before redirecting to the owned
// loopback listener; an ephemeral fixture port must not mask a 389/636 mistake.
type portableDiscoveryPortWire struct {
	wire *portableLDAPWire
	port uint16
}

func (w portableDiscoveryPortWire) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != net.JoinHostPort(portableTLSHost, strconv.FormatUint(uint64(w.port), 10)) || w.port == 0 {
		return nil, errors.New("discovery transport changed the explicitly selected endpoint")
	}
	return w.wire.DialContext(ctx, network, address)
}
