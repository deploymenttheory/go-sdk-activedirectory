package activedirectory

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const (
	topDomain         = "DC=example,DC=test"
	topConfig         = "CN=Configuration," + topDomain
	topSchema         = "CN=Schema," + topConfig
	topPartitions     = "CN=Partitions," + topConfig
	topSites          = "CN=Sites," + topConfig
	topSite           = "CN=London\\, UK," + topSites
	topServer         = "CN=DC\\,1,CN=Servers," + topSite
	topServerRO       = "CN=DC2,CN=Servers," + topSite
	topDSA            = "CN=NTDS Settings," + topServer
	topDSARO          = "CN=NTDS Settings," + topServerRO
	topComputer       = "CN=DC1,OU=Servers," + topDomain
	topComputerRO     = "CN=DC2,OU=Servers," + topDomain
	topSystem         = "OU=Redirected System," + topDomain
	topInfrastructure = "CN=Redirected Infrastructure," + topDomain
	topRID            = "CN=RID Manager," + topSystem
	topCategory       = "CN=NTDS-DSA," + topSchema
	topCategoryRO     = "CN=NTDS-DSA-RO," + topSchema
	topCrossRef       = "CN=EXAMPLE," + topPartitions
	topTrust          = "CN=partner.test," + topSystem
)

// This is an injected LDAP transcript, not a real AD/trust fixture. It checks
// query scope, joins, observation/error semantics and context propagation only.
type topologyFixture struct {
	objects         map[string]Object
	root            map[string][][]byte
	queries         []SearchOptions
	deadlines       []time.Time
	failBase        string
	failure         error
	pageFailureBase string
	pageFailure     error
	before          func(context.Context, SearchOptions) error
}

func topologyObject(dn string, values map[string][]string) Object {
	result := Object{DistinguishedName: dn, Attributes: map[string][][]byte{}}
	for name, texts := range values {
		for _, value := range texts {
			result.Attributes[strings.ToLower(name)] = append(result.Attributes[strings.ToLower(name)], []byte(value))
		}
	}
	return result
}

func newTopologyFixture() *topologyFixture {
	f := &topologyFixture{objects: map[string]Object{}}
	f.root = topologyObject("", map[string][]string{"supportedCapabilities": {CapabilityActiveDirectory}, "defaultNamingContext": {topDomain}, "rootDomainNamingContext": {topDomain}, "configurationNamingContext": {topConfig}, "schemaNamingContext": {topSchema}, "serverName": {topServer}, "dsServiceName": {topDSA}, "isGlobalCatalogReady": {"FALSE"}}).Attributes
	add := func(dn string, values map[string][]string) { f.objects[dn] = topologyObject(dn, values) }
	add(topDomain, map[string][]string{"name": {"example"}, "msDS-Behavior-Version": {"7"}, "msDS-AllowedDNSSuffixes": {"alternate.test"}, "msDS-LogonTimeSyncInterval": {"14"}, "managedBy": {"CN=owner," + topDomain}, "fSMORoleOwner": {topDSA}, "rIDManagerReference": {topRID}, "wellKnownObjects": {"B:32:" + wellKnownSystem + ":" + topSystem, "B:32:" + wellKnownInfrastructure + ":" + topInfrastructure, "B:32:AA312825768811D1ADED00C04FD8D5CD:OU=Moved Computers," + topDomain}})
	add(topCrossRef, map[string][]string{"nCName": {topDomain}, "dnsRoot": {"example.test"}, "nETBIOSName": {"EXAMPLE"}, "systemFlags": {"3"}, "enabled": {"TRUE"}})
	add("CN=CHILD,"+topPartitions, map[string][]string{"nCName": {"DC=child," + topDomain}, "dnsRoot": {"child.example.test"}, "systemFlags": {"3"}, "trustParent": {topCrossRef}, "enabled": {"FALSE"}})
	add("CN=APP,"+topPartitions, map[string][]string{"nCName": {"DC=App," + topDomain}, "dnsRoot": {"app.example.test"}, "systemFlags": {"1"}})
	add("CN=EXT,"+topPartitions, map[string][]string{"nCName": {"DC=external,DC=test"}, "dnsRoot": {"external.test"}, "systemFlags": {"0"}})
	add(topPartitions, map[string][]string{"msDS-Behavior-Version": {"10"}, "uPNSuffixes": {"login.test"}, "msDS-SPNSuffixes": {"service.test"}, "fSMORoleOwner": {topDSA}})
	add(topSchema, map[string][]string{"fSMORoleOwner": {topDSARO}})
	add(topRID, map[string][]string{"fSMORoleOwner": {topDSA}})
	add(topInfrastructure, map[string][]string{"fSMORoleOwner": {topDSARO}})
	add(topCategory, map[string][]string{"lDAPDisplayName": {"nTDSDSA"}})
	add(topCategoryRO, map[string][]string{"lDAPDisplayName": {"nTDSDSARO"}})
	add(topServer, map[string][]string{"dnsHostName": {"dc1.example.test"}, "serverReference": {topComputer}})
	add(topServerRO, map[string][]string{"dnsHostName": {"dc2.example.test"}, "serverReference": {topComputerRO}})
	add(topDSA, map[string][]string{"objectCategory": {topCategory}, "options": {"1"}, "msDS-HasDomainNCs": {topDomain}, "msDS-Behavior-Version": {"7"}, "msDS-hasMasterNCs": {topDomain, topConfig, topSchema}, "hasPartialReplicaNCs": {"DC=child," + topDomain}})
	add(topDSARO, map[string][]string{"objectCategory": {topCategoryRO}, "options": {"0"}, "msDS-HasDomainNCs": {topDomain}, "msDS-Behavior-Version": {"10"}, "msDS-hasFullReplicaNCs": {topDomain, topConfig, topSchema}})
	add(topComputer, map[string][]string{"sAMAccountName": {"DC1$"}, "userAccountControl": {"8192"}, "operatingSystem": {"Windows Server 2022"}, "operatingSystemVersion": {"10.0"}})
	add(topComputerRO, map[string][]string{"sAMAccountName": {"DC2$"}, "userAccountControl": {"8194"}, "operatingSystem": {"Windows Server 2025"}})
	add(topSite, map[string][]string{"name": {"London, UK"}})
	add(topTrust, map[string][]string{"name": {"partner.test"}, "trustPartner": {"partner.test"}, "flatName": {"PARTNER"}, "trustDirection": {"1"}, "trustType": {"99"}, "trustAttributes": {"-2147483640"}, "vendor-binary": {"\x00\xff"}})
	for i, dn := range []string{topDomain, topDSA, topDSARO, topServer, topServerRO, topTrust} {
		f.objects[dn].Attributes["objectguid"] = [][]byte{bytes.Repeat([]byte{byte(i + 1)}, 16)}
	}
	f.objects[topDSA].Attributes["invocationid"] = [][]byte{bytes.Repeat([]byte{20}, 16)}
	f.objects[topTrust].Attributes["securityidentifier"] = [][]byte{{1, 2, 0, 255}}
	return f
}

func (f *topologyFixture) client(timeout time.Duration) *Client {
	return newClient(Config{Endpoint: Endpoint{Host: "dc1.example.test", Port: 389}, Timeout: timeout}, testSession{
		read: func(ctx context.Context, _ []string) (map[string][][]byte, error) {
			deadline, _ := ctx.Deadline()
			f.deadlines = append(f.deadlines, deadline)
			return f.root, nil
		},
		search: func(ctx context.Context, options SearchOptions) (searchCursor, error) {
			f.queries = append(f.queries, options)
			deadline, _ := ctx.Deadline()
			f.deadlines = append(f.deadlines, deadline)
			if f.before != nil {
				if err := f.before(ctx, options); err != nil {
					return nil, err
				}
			}
			if options.Base == f.failBase {
				return nil, f.failure
			}
			var dns []string
			switch options.Scope {
			case ScopeBase:
				if _, ok := f.objects[options.Base]; ok {
					dns = []string{options.Base}
				}
			case ScopeOneLevel:
				switch options.Base {
				case topPartitions:
					dns = []string{topCrossRef, "CN=CHILD," + topPartitions, "CN=APP," + topPartitions, "CN=EXT," + topPartitions}
				case topSites:
					dns = []string{topSite}
				case topServer:
					dns = []string{topDSA}
				case topServerRO:
					dns = []string{topDSARO}
				case topSystem:
					dns = []string{topTrust}
				}
			case ScopeSubtree:
				if options.Base == topSites || options.Base == "CN=Servers,"+topSite {
					dns = []string{topDSA, topDSARO}
					if strings.Contains(options.Filter, "1.2.840.113556.1.4.803") {
						dns = dns[:1]
					}
				}
			}
			index := 0
			return testSearchCursor{read: func(_ context.Context, size uint32) ([]Object, bool, error) {
				var rows []Object
				for index < len(dns) && len(rows) < int(size) {
					source := f.objects[dns[index]]
					index++
					row := Object{DistinguishedName: source.DistinguishedName, Attributes: map[string][][]byte{}}
					for name, values := range source.Attributes {
						if slices.Contains(options.Properties, "*") || slices.ContainsFunc(options.Properties, func(p string) bool {
							return strings.EqualFold(p, name) || strings.HasPrefix(name, strings.ToLower(p)+";range=")
						}) {
							for _, v := range values {
								row.Attributes[name] = append(row.Attributes[name], slices.Clone(v))
							}
						}
					}
					rows = append(rows, row)
				}
				if options.Base == f.pageFailureBase {
					return rows, false, f.pageFailure
				}
				return rows, index == len(dns), nil
			}, finish: func() error { return nil }}, nil
		}, finish: func() error { return nil },
	})
}

func TestDirectoryDomainAndForestJoins(t *testing.T) {
	f := newTopologyFixture()
	client := f.client(time.Second)
	defer client.Close()
	domain, err := client.Directory().Domain(context.Background(), DomainOptions{})
	if err != nil || !domain.Observation.Complete {
		t.Fatalf("domain: %v", err)
	}
	if *domain.DNSRoot != "example.test" || *domain.FunctionalLevel != 7 || len(domain.Children) != 1 || domain.Children[0].Enabled == nil || *domain.Children[0].Enabled {
		t.Fatalf("domain refs: %+v", domain)
	}
	if domain.WellKnownContainers["AA312825768811D1ADED00C04FD8D5CD"] != "OU=Moved Computers,"+topDomain || *domain.RIDMaster.HostName != "dc1.example.test" || *domain.InfrastructureMaster.HostName != "dc2.example.test" {
		t.Fatal("redirection/role joins lost")
	}
	if len(domain.Replicas) != 2 || *domain.Replicas[0].IsReadOnly || !*domain.Replicas[1].IsReadOnly || *domain.Replicas[1].Functionality != 10 {
		t.Fatal("replica type/generation lost")
	}
	forest, err := client.Directory().Forest(context.Background())
	if err != nil || !forest.Observation.Complete || *forest.FunctionalLevel != 10 || len(forest.Domains) != 2 || len(forest.ApplicationPartitions) != 1 || len(forest.ExternalReferences) != 1 || len(forest.GlobalCatalogs) != 1 || *forest.Sites[0].Name != "London, UK" {
		t.Fatalf("forest: %+v %v", forest, err)
	}
	if *forest.SchemaMaster.HostName != "dc2.example.test" || *forest.DomainNamingMaster.HostName != "dc1.example.test" {
		t.Fatal("forest role owner used wrong NC")
	}
}

func TestDirectoryControllerIdentityAndCriteria(t *testing.T) {
	f := newTopologyFixture()
	client := f.client(time.Second)
	defer client.Close()
	result, err := client.Directory().DomainController(context.Background(), DomainControllerOptions{})
	c := result.Controller
	if err != nil || !result.Observation.Complete {
		t.Fatalf("controller: %v", err)
	}
	if *c.SiteName != "London, UK" || !*c.Enabled || !*c.IsGlobalCatalog || c.GlobalCatalogReady == nil || *c.GlobalCatalogReady || len(c.Partitions) != 4 || !c.OperationMasterRolesKnown {
		t.Fatalf("controller facts: %+v", c)
	}
	if bytes.Equal(c.InvocationID, c.NTDSSettingsObjectGUID) || bytes.Equal(c.ServerObjectGUID, c.NTDSSettingsObjectGUID) || !reflect.DeepEqual(c.OperationMasterRoles, []FSMORole{RolePDCEmulator, RoleRIDMaster, RoleDomainNamingMaster}) {
		t.Fatal("identifiers/roles conflated")
	}
	readOnly := true
	list, err := client.Directory().DomainControllers(context.Background(), DomainControllersQuery{SiteDN: topSite, IsReadOnly: &readOnly, PageSize: 1, ResultLimit: 1})
	if err != nil || len(list.Controllers) != 1 || !list.LimitReached || list.Observation.Complete || *list.Controllers[0].Enabled || list.Controllers[0].Settings.DistinguishedName != topDSARO || list.Controllers[0].GlobalCatalogReady != nil {
		t.Fatalf("filtered limit: %+v %v", list, err)
	}
	for _, query := range f.queries {
		if query.Scope == ScopeSubtree && !strings.Contains(query.Filter, "(msDS-HasDomainNCs="+topDomain+")") {
			t.Fatal("domain scope was omitted from Sites search")
		}
	}
}

func TestDirectoryTrustRawProjectionAndLDSQuery(t *testing.T) {
	f := newTopologyFixture()
	f.root["supportedcapabilities"] = [][]byte{[]byte(CapabilityADLDS)}
	client := f.client(time.Second)
	defer client.Close()
	result, err := client.Directory().Trusts(context.Background(), TrustQuery{BaseDN: topSystem, LDAPFilter: "(trustDirection=1)", Properties: []string{"vendor-binary"}})
	if err != nil || !result.Observation.Complete || len(result.Trusts) != 1 {
		t.Fatalf("LDS LDAP projection: %v", err)
	}
	trust := result.Trusts[0]
	if *trust.Direction != 1 || *trust.Type != 99 || *trust.AttributesMask != 0x80000008 || !bytes.Equal(trust.SecurityIdentifier, []byte{1, 2, 0, 255}) {
		t.Fatalf("trust metadata: %+v", trust)
	}
	if values, state := trust.Raw.Attribute("vendor-binary"); state != AttributePresent || !bytes.Equal(values[0], []byte{0, 255}) {
		t.Fatal("selected binary property lost")
	}
	if _, state := trust.Raw.Attribute("trustAuthIncoming"); state != AttributeUnloaded {
		t.Fatal("secret was requested by default")
	}
	last := f.queries[len(f.queries)-1]
	if last.Filter != "(&(objectClass=trustedDomain)(trustDirection=1))" || last.Scope != ScopeOneLevel {
		t.Fatalf("trust query: %+v", last)
	}
	if _, err := client.Directory().Domain(context.Background(), DomainOptions{}); !errors.Is(err, ErrUnsupportedDirectory) {
		t.Fatalf("LDS domain guard: %v", err)
	}
}

func TestDirectoryPartialJoinKeepsRawAndNativeError(t *testing.T) {
	f := newTopologyFixture()
	f.failBase = topRID
	f.failure = &LDAPError{Operation: "Search", Code: 50, Diagnostic: "private"}
	client := f.client(time.Second)
	defer client.Close()
	domain, err := client.Directory().Domain(context.Background(), DomainOptions{})
	var native *LDAPError
	var partial *DirectoryReadError
	if !errors.As(err, &native) || native.Code != 50 || !errors.As(err, &partial) || !errors.Is(err, ErrIncompleteResult) || domain.Observation.Complete || domain.Raw.DistinguishedName != topDomain || domain.PDCEmulator == nil || len(domain.Observation.Objects) == 0 {
		t.Fatalf("partial: %+v %v", domain, err)
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("diagnostic leaked")
	}
}

func TestDirectoryWholeOperationDeadlineAndCancellation(t *testing.T) {
	// This fixture has no native I/O. Advance its timers deterministically so
	// runner scheduling cannot consume the deadline before the first result.
	synctest.Test(t, func(t *testing.T) {
		f := newTopologyFixture()
		client := f.client(35 * time.Millisecond)
		defer client.Close()
		f.before = func(ctx context.Context, _ SearchOptions) error {
			select {
			case <-time.After(12 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		result, err := client.Directory().Domain(context.Background(), DomainOptions{})
		if !errors.Is(err, context.DeadlineExceeded) || result.Observation.Complete || result.Raw.DistinguishedName == "" {
			t.Fatalf("deadline/partial: %v", err)
		}
		if len(f.deadlines) < 3 {
			t.Fatal("did not exercise sequential reads")
		}
		for _, deadline := range f.deadlines {
			if !deadline.Equal(f.deadlines[0]) {
				t.Fatal("composite deadline restarted between reads")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		before := len(f.queries)
		if _, err := client.Directory().Forest(ctx); !errors.Is(err, context.Canceled) || len(f.queries) != before {
			t.Fatalf("pre-canceled dispatch: %v", err)
		}
	})
}

func TestDirectoryMalformedAndUnreturnedValues(t *testing.T) {
	for _, mode := range []string{"bad-guid", "bad-cardinality", "bad-wellknown", "missing-container", "range", "missing-category"} {
		t.Run(mode, func(t *testing.T) {
			f := newTopologyFixture()
			client := f.client(time.Second)
			defer client.Close()
			switch mode {
			case "bad-guid":
				f.objects[topTrust].Attributes["objectguid"] = [][]byte{{1}}
			case "bad-cardinality":
				f.objects[topTrust].Attributes["trustdirection"] = [][]byte{[]byte("1"), []byte("2")}
			case "bad-wellknown":
				f.objects[topDomain].Attributes["wellknownobjects"] = [][]byte{[]byte("B:32:not-a-guid:CN=x")}
			case "missing-container":
				delete(f.objects[topDomain].Attributes, "wellknownobjects")
			case "range":
				delete(f.objects[topTrust].Attributes, "vendor-binary")
				f.objects[topTrust].Attributes["vendor-binary;range=0-1"] = [][]byte{{1}, {2}}
			case "missing-category":
				delete(f.objects[topDSA].Attributes, "objectcategory")
			}
			if mode == "missing-category" {
				gc := true
				ro := false
				result, err := client.Directory().DomainControllers(context.Background(), DomainControllersQuery{IsGlobalCatalog: &gc, IsReadOnly: &ro})
				if !errors.Is(err, ErrIncompleteResult) || result.Observation.Complete || len(result.Controllers) != 0 {
					t.Fatalf("unknown criterion: %v", err)
				}
				return
			}
			result, err := client.Directory().Trusts(context.Background(), TrustQuery{Properties: []string{"vendor-binary"}})
			if err == nil || result.Observation.Complete {
				t.Fatalf("malformed/partial accepted: %+v", result)
			}
			if mode == "range" {
				if _, state := result.Trusts[0].Raw.Attribute("vendor-binary"); state != AttributePartial {
					t.Fatal("partial attribute state was lost")
				}
			}
		})
	}
}

func TestDirectoryEmptyAndPartialSearchOutcomes(t *testing.T) {
	f := newTopologyFixture()
	client := f.client(time.Second)
	defer client.Close()
	missing, err := client.Directory().Trust(context.Background(), "CN=absent,"+topSystem, TrustOptions{})
	if !errors.Is(err, ErrDirectoryObjectNotFound) || missing.Observation.Complete {
		t.Fatalf("empty identity: %v", err)
	}
	empty, err := client.Directory().Trusts(context.Background(), TrustQuery{BaseDN: "OU=empty," + topDomain})
	if err != nil || !empty.Observation.Complete || len(empty.Trusts) != 0 {
		t.Fatalf("empty collection: %v", err)
	}
	f.pageFailureBase = topSystem
	f.pageFailure = &LDAPError{Operation: "Search", Code: 4}
	partial, err := client.Directory().Trusts(context.Background(), TrustQuery{BaseDN: topSystem})
	var native *LDAPError
	if !errors.As(err, &native) || native.Code != 4 || partial.Observation.Complete || len(partial.Trusts) != 1 || partial.Trusts[0].Raw.DistinguishedName != topTrust {
		t.Fatalf("partial page discarded: %+v %v", partial, err)
	}
}

func TestDirectoryDeadlineIncludesQueuedInitialRead(t *testing.T) {
	f := newTopologyFixture()
	client := f.client(30 * time.Millisecond)
	defer client.Close()
	<-client.gate
	defer func() { client.gate <- struct{}{} }()
	result, err := client.Directory().Forest(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || result.Observation.Complete || len(f.deadlines) != 0 || len(f.queries) != 0 {
		t.Fatalf("queued budget: %v", err)
	}
}

func TestDirectoryRoleIdentitySurvivesHostFailure(t *testing.T) {
	f := newTopologyFixture()
	f.failBase = topServer
	f.failure = &LDAPError{Operation: "Search", Code: 50}
	client := f.client(time.Second)
	defer client.Close()
	domain, err := client.Directory().Domain(context.Background(), DomainOptions{})
	if err == nil || domain.Observation.Complete || domain.PDCEmulator == nil || domain.PDCEmulator.NTDSSettingsDN != topDSA || domain.PDCEmulator.ServerDN != topServer || domain.PDCEmulator.HostName != nil {
		t.Fatalf("role identity lost: %+v %v", domain.PDCEmulator, err)
	}
}

func TestDirectoryMissingDefaultIsNotLDSInference(t *testing.T) {
	f := newTopologyFixture()
	delete(f.root, "defaultnamingcontext")
	client := f.client(time.Second)
	defer client.Close()
	result, err := client.Directory().Domain(context.Background(), DomainOptions{})
	if !errors.Is(err, ErrIncompleteResult) || errors.Is(err, ErrUnsupportedDirectory) || result.Observation.RootDSE.Capabilities().Type != DirectoryADDS || len(f.queries) != 0 {
		t.Fatalf("missing default/capability: %v", err)
	}
	delete(f.root, "supportedcapabilities")
	_, err = client.Directory().Forest(context.Background())
	var capability *DirectoryCapabilityError
	if !errors.As(err, &capability) || capability.Actual != DirectoryUnknown || len(f.queries) != 0 {
		t.Fatalf("unknown capability: %v", err)
	}
}

func TestDirectoryValidationAndLiteralEscaping(t *testing.T) {
	var client *Client
	if _, err := client.Directory().Trust(context.Background(), "", TrustOptions{}); !errors.Is(err, ErrInvalidDirectoryQuery) {
		t.Fatal(err)
	}
	if _, err := client.Directory().Trusts(context.Background(), TrustQuery{BaseDN: "a", DomainDN: "b"}); !errors.Is(err, ErrInvalidDirectoryQuery) {
		t.Fatal(err)
	}
	if _, err := client.Directory().Domain(context.Background(), DomainOptions{DistinguishedName: "a\x00b"}); !errors.Is(err, ErrInvalidDirectoryQuery) {
		t.Fatal(err)
	}
	if _, err := client.Directory().Forest(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if got := ldapLiteral("a*(b)\\\x00é"); got != "a\\2a\\28b\\29\\5c\\00é" {
		t.Fatalf("literal: %q", got)
	}
	if parent, err := parentDirectoryDN(topServer); err != nil || parent != "CN=Servers,"+topSite {
		t.Fatalf("escaped parent: %s %v", parent, err)
	}
}
