package dccloning

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

type configDirectoryFixture struct {
	root                ad.RootDSE
	objects             map[string]ad.Object
	searchErr, closeErr error
	incomplete          bool
	closed              int
	searches            []ad.SearchOptions
}

func (f *configDirectoryFixture) RootDSE(context.Context, ad.RootDSEOptions) (ad.RootDSE, error) {
	return f.root, nil
}
func (f *configDirectoryFixture) Search(_ context.Context, options ad.SearchOptions) (ad.SearchResult, error) {
	f.searches = append(f.searches, options)
	if f.searchErr != nil {
		return ad.SearchResult{}, f.searchErr
	}
	object, ok := f.objects[options.Base]
	if !ok {
		return ad.SearchResult{Complete: true}, nil
	}
	object.RequestedProperties = options.Properties
	return ad.SearchResult{Complete: !f.incomplete, Objects: []ad.Object{object}}, nil
}
func (f *configDirectoryFixture) Close() error { f.closed++; return f.closeErr }

func cloneDirectoryFixture(t *testing.T) (configDirectoryAPI, *configDirectoryFixture, *configDirectoryFixture) {
	t.Helper()
	pointer := func(s string) *string { return &s }
	functionality := uint32(7)
	root := ad.RootDSE{DNSHostName: pointer("source.example.test"), DefaultNamingContext: pointer("DC=example,DC=test"), ServerName: pointer("CN=Source,CN=Servers"), DSServiceName: pointer("CN=NTDS Settings,CN=Source,CN=Servers"), DomainControllerFunctionality: &functionality, SupportedCapabilities: []string{ad.CapabilityActiveDirectory}}
	domainSID := []byte{1, 4, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0}
	computerSID := append(append([]byte{}, domainSID...), 0, 0, 0, 0)
	computerSID[1]++
	binary.LittleEndian.PutUint32(computerSID[len(domainSID):], 1001)
	group, err := cloneGroupSID(domainSID)
	if err != nil {
		t.Fatal(err)
	}
	computerDN := "CN=Source,OU=Domain Controllers,DC=example,DC=test"
	object := func(dn string, attrs map[string][][]byte) ad.Object {
		return ad.Object{DistinguishedName: dn, Attributes: attrs}
	}
	source := &configDirectoryFixture{root: root, objects: map[string]ad.Object{
		*root.ServerName: object(*root.ServerName, map[string][][]byte{"serverreference": {[]byte(computerDN)}}),
		computerDN:       object(computerDN, map[string][][]byte{"objectguid": {make([]byte, 16)}, "objectsid": {computerSID}}),
	}}
	root.DNSHostName = pointer("pdc.example.test")
	root.DSServiceName = pointer("CN=NTDS Settings,CN=PDC,CN=Servers")
	primary := &configDirectoryFixture{root: root, objects: map[string]ad.Object{
		*root.DefaultNamingContext: object(*root.DefaultNamingContext, map[string][][]byte{"objectsid": {domainSID}, "fsmoroleowner": {[]byte(*root.DSServiceName)}}),
		computerDN:                 object(computerDN, map[string][][]byte{"objectguid": {make([]byte, 16)}, "objectsid": {computerSID}, "tokengroups": {computerSID, group}}),
	}}
	api := configDirectoryAPI{
		dial: func(_ context.Context, config ad.Config) (configConnection, error) {
			switch config.Endpoint.Host {
			case "source.example.test":
				return source, nil
			case "pdc.example.test":
				return primary, nil
			default:
				t.Fatalf("unexpected host %s", config.Endpoint.Host)
				return nil, ErrIncomplete
			}
		},
		discover: func(_ context.Context, options ad.DiscoveryOptions) (ad.DiscoveredController, error) {
			if options.Services != ad.ServicePrimaryDC || options.MinimumVersion != ad.DirectoryServiceWindows2012 || !options.ForceDiscover {
				t.Fatalf("discovery: %#v", options)
			}
			return ad.DiscoveredController{ControllerName: `\\pdc.example.test`}, nil
		},
	}
	return api, source, primary
}

func TestCloneDirectoryAuthenticatedPrerequisites(t *testing.T) {
	api, source, primary := cloneDirectoryFixture(t)
	var result ConfigPrerequisites
	if err := checkCloneDirectory(context.Background(), "source.example.test", api, &result); err != nil {
		t.Fatal(err)
	}
	if !result.CloneableGroupMember || result.PrimaryController != "pdc.example.test" || result.PrimaryFunctionality == nil || result.SourceComputerDN == "" {
		t.Fatalf("%#v", result)
	}
	if source.closed != 1 || primary.closed != 1 {
		t.Fatalf("close counts %d/%d", source.closed, primary.closed)
	}
	if len(source.searches) != 2 || len(primary.searches) != 2 {
		t.Fatalf("search counts %d/%d", len(source.searches), len(primary.searches))
	}
	for _, query := range append(source.searches, primary.searches...) {
		if query.Scope != ad.ScopeBase || len(query.Properties) == 0 {
			t.Fatalf("unbounded query: %#v", query)
		}
	}
	if !reflect.DeepEqual(primary.searches[1].Properties, []string{"objectGUID", "objectSid", "tokenGroups"}) {
		t.Fatalf("membership projection: %v", primary.searches[1].Properties)
	}
}

func TestCloneDirectoryRejectsIncompleteOrStaleEvidence(t *testing.T) {
	for _, scenario := range []string{"source old", "source LDS", "source missing hostname", "source partial search", "source missing server reference", "source malformed SID", "PDC old", "PDC different domain", "PDC stale role", "PDC different GUID", "PDC missing groups", "PDC malformed group", "PDC not member", "PDC unreadable", "close failure"} {
		t.Run(scenario, func(t *testing.T) {
			api, source, primary := cloneDirectoryFixture(t)
			var result ConfigPrerequisites
			sentinel := errors.New("denied or cleanup failed")
			want := ErrIncomplete
			computerDN := "CN=Source,OU=Domain Controllers,DC=example,DC=test"
			domain := *source.root.DefaultNamingContext
			switch scenario {
			case "source old":
				v := uint32(4)
				source.root.DomainControllerFunctionality = &v
				want = ErrClonePrerequisite
			case "source LDS":
				source.root.SupportedCapabilities = []string{"1.2.840.113556.1.4.1851"}
				want = nil
			case "source missing hostname":
				source.root.DNSHostName = nil
			case "source partial search":
				source.incomplete = true
			case "source missing server reference":
				delete(source.objects[*source.root.ServerName].Attributes, "serverreference")
			case "source malformed SID":
				source.objects[computerDN].Attributes["objectsid"] = [][]byte{{1, 4}}
			case "PDC old":
				v := uint32(4)
				primary.root.DomainControllerFunctionality = &v
				want = ErrClonePrerequisite
			case "PDC different domain":
				v := "DC=another,DC=test"
				primary.root.DefaultNamingContext = &v
				want = ErrClonePrerequisite
			case "PDC stale role":
				primary.objects[domain].Attributes["fsmoroleowner"] = [][]byte{[]byte("CN=other")}
				want = ErrClonePrerequisite
			case "PDC different GUID":
				primary.objects[computerDN].Attributes["objectguid"] = [][]byte{[]byte("different-guid!!")}
				want = ErrClonePrerequisite
			case "PDC missing groups":
				delete(primary.objects[computerDN].Attributes, "tokengroups")
			case "PDC malformed group":
				primary.objects[computerDN].Attributes["tokengroups"] = [][]byte{{1, 15}}
			case "PDC not member":
				primary.objects[computerDN].Attributes["tokengroups"] = primary.objects[computerDN].Attributes["objectsid"]
				want = ErrClonePrerequisite
			case "PDC unreadable":
				primary.searchErr = sentinel
				want = sentinel
			case "close failure":
				source.closeErr = sentinel
				primary.closeErr = sentinel
				want = sentinel
			}
			err := checkCloneDirectory(context.Background(), "source.example.test", api, &result)
			if err == nil || want != nil && !errors.Is(err, want) {
				t.Fatalf("%#v / %v; want %v", result, err, want)
			}
			wantPrimaryClosed := 1
			if strings.HasPrefix(scenario, "source ") {
				wantPrimaryClosed = 0
			}
			if source.closed != 1 || primary.closed != wantPrimaryClosed {
				t.Fatalf("close counts %d/%d", source.closed, primary.closed)
			}
		})
	}
}

func TestCloneDirectoryBindFailuresCloseOnlyOwnedConnections(t *testing.T) {
	for _, failHost := range []string{"source.example.test", "pdc.example.test"} {
		t.Run(failHost, func(t *testing.T) {
			api, source, primary := cloneDirectoryFixture(t)
			dial := api.dial
			sentinel := errors.New("bind failed")
			api.dial = func(ctx context.Context, config ad.Config) (configConnection, error) {
				if config.Endpoint.Host == failHost {
					return nil, sentinel
				}
				return dial(ctx, config)
			}
			var evidence ConfigPrerequisites
			err := checkCloneDirectory(context.Background(), "source.example.test", api, &evidence)
			wantSource := 0
			if failHost == "pdc.example.test" {
				wantSource = 1
			}
			if !errors.Is(err, sentinel) || source.closed != wantSource || primary.closed != 0 {
				t.Fatalf("%v closes %d/%d", err, source.closed, primary.closed)
			}
		})
	}
}
