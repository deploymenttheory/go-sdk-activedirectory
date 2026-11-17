package acceptance

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

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

const (
	InternalTopDomain         = "DC=example,DC=test"
	InternalTopConfig         = "CN=Configuration," + InternalTopDomain
	InternalTopSchema         = "CN=Schema," + InternalTopConfig
	InternalTopPartitions     = "CN=Partitions," + InternalTopConfig
	InternalTopSites          = "CN=Sites," + InternalTopConfig
	InternalTopSite           = "CN=London\\, UK," + InternalTopSites
	InternalTopServer         = "CN=DC\\,1,CN=Servers," + InternalTopSite
	InternalTopServerRO       = "CN=DC2,CN=Servers," + InternalTopSite
	InternalTopDSA            = "CN=NTDS Settings," + InternalTopServer
	InternalTopDSARO          = "CN=NTDS Settings," + InternalTopServerRO
	InternalTopComputer       = "CN=DC1,OU=Servers," + InternalTopDomain
	InternalTopComputerRO     = "CN=DC2,OU=Servers," + InternalTopDomain
	InternalTopSystem         = "OU=Redirected System," + InternalTopDomain
	InternalTopInfrastructure = "CN=Redirected Infrastructure," + InternalTopDomain
	InternalTopRID            = "CN=RID Manager," + InternalTopSystem
	InternalTopCategory       = "CN=NTDS-DSA," + InternalTopSchema
	InternalTopCategoryRO     = "CN=NTDS-DSA-RO," + InternalTopSchema
	InternalTopCrossRef       = "CN=EXAMPLE," + InternalTopPartitions
	InternalTopTrust          = "CN=partner.test," + InternalTopSystem
)

// This is an injected LDAP transcript, not a real AD/trust fixture. It checks
// query scope, joins, observation/error semantics and context propagation only.
type InternalTopologyFixture struct {
	InternalObjects         map[string]admodel.Object
	InternalRoot            map[string][][]byte
	InternalQueries         []admodel.SearchOptions
	InternalDeadlines       []time.Time
	InternalFailBase        string
	InternalFailure         error
	InternalPageFailureBase string
	InternalPageFailure     error
	InternalBefore          func(context.Context, admodel.SearchOptions) error
}

func InternalTopologyObject(dn string, values map[string][]string) admodel.Object {
	result := admodel.Object{DistinguishedName: dn, Attributes: map[string][][]byte{}}
	for name, texts := range values {
		for _, value := range texts {
			result.Attributes[strings.ToLower(name)] = append(
				result.Attributes[strings.ToLower(name)],
				[]byte(value),
			)
		}
	}
	return result
}

func InternalNewTopologyFixture() *InternalTopologyFixture {
	f := &InternalTopologyFixture{InternalObjects: map[string]admodel.Object{}}
	f.InternalRoot = InternalTopologyObject(
		"",
		map[string][]string{
			"supportedCapabilities":      {admodel.CapabilityActiveDirectory},
			"defaultNamingContext":       {InternalTopDomain},
			"rootDomainNamingContext":    {InternalTopDomain},
			"configurationNamingContext": {InternalTopConfig},
			"schemaNamingContext":        {InternalTopSchema},
			"serverName":                 {InternalTopServer},
			"dsServiceName":              {InternalTopDSA},
			"isGlobalCatalogReady":       {"FALSE"},
		},
	).Attributes
	add := func(dn string, values map[string][]string) {
		f.InternalObjects[dn] = InternalTopologyObject(dn, values)
	}
	add(
		InternalTopDomain,
		map[string][]string{
			"name":                       {"example"},
			"msDS-Behavior-Version":      {"7"},
			"msDS-AllowedDNSSuffixes":    {"alternate.test"},
			"msDS-LogonTimeSyncInterval": {"14"},
			"managedBy":                  {"CN=owner," + InternalTopDomain},
			"fSMORoleOwner":              {InternalTopDSA},
			"rIDManagerReference":        {InternalTopRID},
			"wellKnownObjects": {
				"B:32:" + admodel.InternalWellKnownSystem + ":" + InternalTopSystem,
				"B:32:" + admodel.InternalWellKnownInfrastructure + ":" + InternalTopInfrastructure,
				"B:32:AA312825768811D1ADED00C04FD8D5CD:OU=Moved Computers," + InternalTopDomain,
			},
		},
	)
	add(
		InternalTopCrossRef,
		map[string][]string{
			"nCName":      {InternalTopDomain},
			"dnsRoot":     {"example.test"},
			"nETBIOSName": {"EXAMPLE"},
			"systemFlags": {"3"},
			"enabled":     {"TRUE"},
		},
	)
	add(
		"CN=CHILD,"+InternalTopPartitions,
		map[string][]string{
			"nCName":      {"DC=child," + InternalTopDomain},
			"dnsRoot":     {"child.example.test"},
			"systemFlags": {"3"},
			"trustParent": {InternalTopCrossRef},
			"enabled":     {"FALSE"},
		},
	)
	add(
		"CN=APP,"+InternalTopPartitions,
		map[string][]string{
			"nCName":      {"DC=App," + InternalTopDomain},
			"dnsRoot":     {"app.example.test"},
			"systemFlags": {"1"},
		},
	)
	add(
		"CN=EXT,"+InternalTopPartitions,
		map[string][]string{
			"nCName":      {"DC=external,DC=test"},
			"dnsRoot":     {"external.test"},
			"systemFlags": {"0"},
		},
	)
	add(
		InternalTopPartitions,
		map[string][]string{
			"msDS-Behavior-Version": {"10"},
			"uPNSuffixes":           {"login.test"},
			"msDS-SPNSuffixes":      {"service.test"},
			"fSMORoleOwner":         {InternalTopDSA},
		},
	)
	add(InternalTopSchema, map[string][]string{"fSMORoleOwner": {InternalTopDSARO}})
	add(InternalTopRID, map[string][]string{"fSMORoleOwner": {InternalTopDSA}})
	add(InternalTopInfrastructure, map[string][]string{"fSMORoleOwner": {InternalTopDSARO}})
	add(InternalTopCategory, map[string][]string{"lDAPDisplayName": {"nTDSDSA"}})
	add(InternalTopCategoryRO, map[string][]string{"lDAPDisplayName": {"nTDSDSARO"}})
	add(
		InternalTopServer,
		map[string][]string{
			"dnsHostName":     {"dc1.example.test"},
			"serverReference": {InternalTopComputer},
		},
	)
	add(
		InternalTopServerRO,
		map[string][]string{
			"dnsHostName":     {"dc2.example.test"},
			"serverReference": {InternalTopComputerRO},
		},
	)
	add(
		InternalTopDSA,
		map[string][]string{
			"objectCategory":        {InternalTopCategory},
			"options":               {"1"},
			"msDS-HasDomainNCs":     {InternalTopDomain},
			"msDS-Behavior-Version": {"7"},
			"msDS-hasMasterNCs":     {InternalTopDomain, InternalTopConfig, InternalTopSchema},
			"hasPartialReplicaNCs":  {"DC=child," + InternalTopDomain},
		},
	)
	add(
		InternalTopDSARO,
		map[string][]string{
			"objectCategory":         {InternalTopCategoryRO},
			"options":                {"0"},
			"msDS-HasDomainNCs":      {InternalTopDomain},
			"msDS-Behavior-Version":  {"10"},
			"msDS-hasFullReplicaNCs": {InternalTopDomain, InternalTopConfig, InternalTopSchema},
		},
	)
	add(
		InternalTopComputer,
		map[string][]string{
			"sAMAccountName":         {"DC1$"},
			"userAccountControl":     {"8192"},
			"operatingSystem":        {"Windows Server 2022"},
			"operatingSystemVersion": {"10.0"},
		},
	)
	add(
		InternalTopComputerRO,
		map[string][]string{
			"sAMAccountName":     {"DC2$"},
			"userAccountControl": {"8194"},
			"operatingSystem":    {"Windows Server 2025"},
		},
	)
	add(InternalTopSite, map[string][]string{"name": {"London, UK"}})
	add(
		InternalTopTrust,
		map[string][]string{
			"name":            {"partner.test"},
			"trustPartner":    {"partner.test"},
			"flatName":        {"PARTNER"},
			"trustDirection":  {"1"},
			"trustType":       {"99"},
			"trustAttributes": {"-2147483640"},
			"vendor-binary":   {"\x00\xff"},
		},
	)
	for i, dn := range []string{InternalTopDomain, InternalTopDSA, InternalTopDSARO, InternalTopServer, InternalTopServerRO, InternalTopTrust} {
		f.InternalObjects[dn].Attributes["objectguid"] = [][]byte{
			bytes.Repeat([]byte{byte(i + 1)}, 16),
		}
	}
	f.InternalObjects[InternalTopDSA].Attributes["invocationid"] = [][]byte{
		bytes.Repeat([]byte{20}, 16),
	}
	f.InternalObjects[InternalTopTrust].Attributes["securityidentifier"] = [][]byte{{1, 2, 0, 255}}
	return f
}

func (f *InternalTopologyFixture) InternalClient(timeout time.Duration) *adengine.Client {
	return adengine.InternalNewClient(
		admodel.Config{
			Endpoint: admodel.Endpoint{Host: "dc1.example.test", Port: 389},
			Timeout:  timeout,
		},
		InternalTestSession{
			InternalRead: func(ctx context.Context, _ []string) (map[string][][]byte, error) {
				deadline, _ := ctx.Deadline()
				f.InternalDeadlines = append(f.InternalDeadlines, deadline)
				return f.InternalRoot, nil
			},
			InternalSearch: func(ctx context.Context, options admodel.SearchOptions) (admodel.InternalSearchCursor, error) {
				f.InternalQueries = append(f.InternalQueries, options)
				deadline, _ := ctx.Deadline()
				f.InternalDeadlines = append(f.InternalDeadlines, deadline)
				if f.InternalBefore != nil {
					if err := f.InternalBefore(ctx, options); err != nil {
						return nil, err
					}
				}
				if options.Base == f.InternalFailBase {
					return nil, f.InternalFailure
				}
				var dns []string
				switch options.Scope {
				case admodel.ScopeBase:
					if _, ok := f.InternalObjects[options.Base]; ok {
						dns = []string{options.Base}
					}
				case admodel.ScopeOneLevel:
					switch options.Base {
					case InternalTopPartitions:
						dns = []string{
							InternalTopCrossRef,
							"CN=CHILD," + InternalTopPartitions,
							"CN=APP," + InternalTopPartitions,
							"CN=EXT," + InternalTopPartitions,
						}
					case InternalTopSites:
						dns = []string{InternalTopSite}
					case InternalTopServer:
						dns = []string{InternalTopDSA}
					case InternalTopServerRO:
						dns = []string{InternalTopDSARO}
					case InternalTopSystem:
						dns = []string{InternalTopTrust}
					}
				case admodel.ScopeSubtree:
					if options.Base == InternalTopSites ||
						options.Base == "CN=Servers,"+InternalTopSite {
						dns = []string{InternalTopDSA, InternalTopDSARO}
						if strings.Contains(options.Filter, "1.2.840.113556.1.4.803") {
							dns = dns[:1]
						}
					}
				}
				index := 0
				return InternalTestSearchCursor{
					InternalRead: func(_ context.Context, size uint32) ([]admodel.Object, bool, error) {
						var rows []admodel.Object
						for index < len(dns) && len(rows) < int(size) {
							source := f.InternalObjects[dns[index]]
							index++
							row := admodel.Object{
								DistinguishedName: source.DistinguishedName,
								Attributes:        map[string][][]byte{},
							}
							for name, values := range source.Attributes {
								if slices.Contains(options.Properties, "*") ||
									slices.ContainsFunc(options.Properties, func(p string) bool {
										return strings.EqualFold(p, name) ||
											strings.HasPrefix(name, strings.ToLower(p)+";range=")
									}) {
									for _, v := range values {
										row.Attributes[name] = append(
											row.Attributes[name],
											slices.Clone(v),
										)
									}
								}
							}
							rows = append(rows, row)
						}
						if options.Base == f.InternalPageFailureBase {
							return rows, false, f.InternalPageFailure
						}
						return rows, index == len(dns), nil
					},
					InternalFinish: func() error { return nil },
				}, nil
			},
			InternalFinish: func() error { return nil },
		},
	)
}

func TestDirectoryDomainAndForestJoins(t *testing.T) {
	f := InternalNewTopologyFixture()
	client := f.InternalClient(time.Second)
	defer client.Close()
	domain, err := client.Directory().Domain(context.Background(), admodel.DomainOptions{})
	if err != nil || !domain.Observation.Complete {
		t.Fatalf("domain: %v", err)
	}
	if *domain.DNSRoot != "example.test" || *domain.FunctionalLevel != 7 ||
		len(domain.Children) != 1 ||
		domain.Children[0].Enabled == nil ||
		*domain.Children[0].Enabled {
		t.Fatalf("domain refs: %+v", domain)
	}
	if domain.WellKnownContainers["AA312825768811D1ADED00C04FD8D5CD"] != "OU=Moved Computers,"+InternalTopDomain ||
		*domain.RIDMaster.HostName != "dc1.example.test" ||
		*domain.InfrastructureMaster.HostName != "dc2.example.test" {
		t.Fatal("redirection/role joins lost")
	}
	if len(domain.Replicas) != 2 || *domain.Replicas[0].IsReadOnly ||
		!*domain.Replicas[1].IsReadOnly ||
		*domain.Replicas[1].Functionality != 10 {
		t.Fatal("replica type/generation lost")
	}
	forest, err := client.Directory().Forest(context.Background())
	if err != nil || !forest.Observation.Complete || *forest.FunctionalLevel != 10 ||
		len(forest.Domains) != 2 ||
		len(forest.ApplicationPartitions) != 1 ||
		len(forest.ExternalReferences) != 1 ||
		len(forest.GlobalCatalogs) != 1 ||
		*forest.Sites[0].Name != "London, UK" {
		t.Fatalf("forest: %+v %v", forest, err)
	}
	if *forest.SchemaMaster.HostName != "dc2.example.test" ||
		*forest.DomainNamingMaster.HostName != "dc1.example.test" {
		t.Fatal("forest role owner used wrong NC")
	}
}

func TestDirectoryControllerIdentityAndCriteria(t *testing.T) {
	f := InternalNewTopologyFixture()
	client := f.InternalClient(time.Second)
	defer client.Close()
	result, err := client.Directory().
		DomainController(context.Background(), admodel.DomainControllerOptions{})
	c := result.Controller
	if err != nil || !result.Observation.Complete {
		t.Fatalf("controller: %v", err)
	}
	if *c.SiteName != "London, UK" || !*c.Enabled || !*c.IsGlobalCatalog ||
		c.GlobalCatalogReady == nil ||
		*c.GlobalCatalogReady ||
		len(c.Partitions) != 4 ||
		!c.OperationMasterRolesKnown {
		t.Fatalf("controller facts: %+v", c)
	}
	if bytes.Equal(c.InvocationID, c.NTDSSettingsObjectGUID) ||
		bytes.Equal(c.ServerObjectGUID, c.NTDSSettingsObjectGUID) ||
		!reflect.DeepEqual(
			c.OperationMasterRoles,
			[]admodel.FSMORole{
				admodel.RolePDCEmulator,
				admodel.RoleRIDMaster,
				admodel.RoleDomainNamingMaster,
			},
		) {
		t.Fatal("identifiers/roles conflated")
	}
	readOnly := true
	list, err := client.Directory().
		DomainControllers(context.Background(), admodel.DomainControllersQuery{SiteDN: InternalTopSite, IsReadOnly: &readOnly, PageSize: 1, ResultLimit: 1})
	if err != nil || len(list.Controllers) != 1 || !list.LimitReached ||
		list.Observation.Complete ||
		*list.Controllers[0].Enabled ||
		list.Controllers[0].Settings.DistinguishedName != InternalTopDSARO ||
		list.Controllers[0].GlobalCatalogReady != nil {
		t.Fatalf("filtered limit: %+v %v", list, err)
	}
	for _, query := range f.InternalQueries {
		if query.Scope == admodel.ScopeSubtree &&
			!strings.Contains(query.Filter, "(msDS-HasDomainNCs="+InternalTopDomain+")") {
			t.Fatal("domain scope was omitted from Sites search")
		}
	}
}

func TestDirectoryTrustRawProjectionAndLDSQuery(t *testing.T) {
	f := InternalNewTopologyFixture()
	f.InternalRoot["supportedcapabilities"] = [][]byte{[]byte(admodel.CapabilityADLDS)}
	client := f.InternalClient(time.Second)
	defer client.Close()
	result, err := client.Directory().
		Trusts(context.Background(), admodel.TrustQuery{BaseDN: InternalTopSystem, LDAPFilter: "(trustDirection=1)", Properties: []string{"vendor-binary"}})
	if err != nil || !result.Observation.Complete || len(result.Trusts) != 1 {
		t.Fatalf("LDS LDAP projection: %v", err)
	}
	trust := result.Trusts[0]
	if *trust.Direction != 1 || *trust.Type != 99 || *trust.AttributesMask != 0x80000008 ||
		!bytes.Equal(trust.SecurityIdentifier, []byte{1, 2, 0, 255}) {
		t.Fatalf("trust metadata: %+v", trust)
	}
	if values, state := trust.Raw.Attribute(
		"vendor-binary",
	); state != admodel.AttributePresent ||
		!bytes.Equal(values[0], []byte{0, 255}) {
		t.Fatal("selected binary property lost")
	}
	if _, state := trust.Raw.Attribute("trustAuthIncoming"); state != admodel.AttributeUnloaded {
		t.Fatal("secret was requested by default")
	}
	last := f.InternalQueries[len(f.InternalQueries)-1]
	if last.Filter != "(&(objectClass=trustedDomain)(trustDirection=1))" ||
		last.Scope != admodel.ScopeOneLevel {
		t.Fatalf("trust query: %+v", last)
	}
	if _, err := client.Directory().
		Domain(context.Background(), admodel.DomainOptions{}); !errors.Is(
		err,
		admodel.ErrUnsupportedDirectory,
	) {
		t.Fatalf("LDS domain guard: %v", err)
	}
}

func TestDirectoryPartialJoinKeepsRawAndNativeError(t *testing.T) {
	f := InternalNewTopologyFixture()
	f.InternalFailBase = InternalTopRID
	f.InternalFailure = &admodel.LDAPError{Operation: "Search", Code: 50, Diagnostic: "private"}
	client := f.InternalClient(time.Second)
	defer client.Close()
	domain, err := client.Directory().Domain(context.Background(), admodel.DomainOptions{})
	var native *admodel.LDAPError
	var partial *admodel.DirectoryReadError
	if !errors.As(err, &native) || native.Code != 50 || !errors.As(err, &partial) ||
		!errors.Is(err, admodel.ErrIncompleteResult) ||
		domain.Observation.Complete ||
		domain.Raw.DistinguishedName != InternalTopDomain ||
		domain.PDCEmulator == nil ||
		len(domain.Observation.Objects) == 0 {
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
		f := InternalNewTopologyFixture()
		client := f.InternalClient(35 * time.Millisecond)
		defer client.Close()
		f.InternalBefore = func(ctx context.Context, _ admodel.SearchOptions) error {
			select {
			case <-time.After(12 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return context.Cause(ctx)
			}
		}
		result, err := client.Directory().Domain(context.Background(), admodel.DomainOptions{})
		if !errors.Is(err, context.DeadlineExceeded) || result.Observation.Complete ||
			result.Raw.DistinguishedName == "" {
			t.Fatalf("deadline/partial: %v", err)
		}
		if len(f.InternalDeadlines) < 3 {
			t.Fatal("did not exercise sequential reads")
		}
		for _, deadline := range f.InternalDeadlines {
			if !deadline.Equal(f.InternalDeadlines[0]) {
				t.Fatal("composite deadline restarted between reads")
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		before := len(f.InternalQueries)
		if _, err := client.Directory().
			Forest(ctx); !errors.Is(err, context.Canceled) ||
			len(f.InternalQueries) != before {
			t.Fatalf("pre-canceled dispatch: %v", err)
		}
	})
}

func TestDirectoryMalformedAndUnreturnedValues(t *testing.T) {
	for _, mode := range []string{"bad-guid", "bad-cardinality", "bad-wellknown", "missing-container", "range", "missing-category"} {
		t.Run(mode, func(t *testing.T) {
			f := InternalNewTopologyFixture()
			client := f.InternalClient(time.Second)
			defer client.Close()
			switch mode {
			case "bad-guid":
				f.InternalObjects[InternalTopTrust].Attributes["objectguid"] = [][]byte{{1}}
			case "bad-cardinality":
				f.InternalObjects[InternalTopTrust].Attributes["trustdirection"] = [][]byte{
					[]byte("1"),
					[]byte("2"),
				}
			case "bad-wellknown":
				f.InternalObjects[InternalTopDomain].Attributes["wellknownobjects"] = [][]byte{
					[]byte("B:32:not-a-guid:CN=x"),
				}
			case "missing-container":
				delete(f.InternalObjects[InternalTopDomain].Attributes, "wellknownobjects")
			case "range":
				delete(f.InternalObjects[InternalTopTrust].Attributes, "vendor-binary")
				f.InternalObjects[InternalTopTrust].Attributes["vendor-binary;range=0-1"] = [][]byte{
					{1},
					{2},
				}
			case "missing-category":
				delete(f.InternalObjects[InternalTopDSA].Attributes, "objectcategory")
			}
			if mode == "missing-category" {
				gc := true
				ro := false
				result, err := client.Directory().
					DomainControllers(context.Background(), admodel.DomainControllersQuery{IsGlobalCatalog: &gc, IsReadOnly: &ro})
				if !errors.Is(err, admodel.ErrIncompleteResult) || result.Observation.Complete ||
					len(result.Controllers) != 0 {
					t.Fatalf("unknown criterion: %v", err)
				}
				return
			}
			result, err := client.Directory().
				Trusts(context.Background(), admodel.TrustQuery{Properties: []string{"vendor-binary"}})
			if err == nil || result.Observation.Complete {
				t.Fatalf("malformed/partial accepted: %+v", result)
			}
			if mode == "range" {
				if _, state := result.Trusts[0].Raw.Attribute(
					"vendor-binary",
				); state != admodel.AttributePartial {
					t.Fatal("partial attribute state was lost")
				}
			}
		})
	}
}

func TestDirectoryEmptyAndPartialSearchOutcomes(t *testing.T) {
	f := InternalNewTopologyFixture()
	client := f.InternalClient(time.Second)
	defer client.Close()
	missing, err := client.Directory().
		Trust(context.Background(), "CN=absent,"+InternalTopSystem, admodel.TrustOptions{})
	if !errors.Is(err, admodel.ErrDirectoryObjectNotFound) || missing.Observation.Complete {
		t.Fatalf("empty identity: %v", err)
	}
	empty, err := client.Directory().
		Trusts(context.Background(), admodel.TrustQuery{BaseDN: "OU=empty," + InternalTopDomain})
	if err != nil || !empty.Observation.Complete || len(empty.Trusts) != 0 {
		t.Fatalf("empty collection: %v", err)
	}
	f.InternalPageFailureBase = InternalTopSystem
	f.InternalPageFailure = &admodel.LDAPError{Operation: "Search", Code: 4}
	partial, err := client.Directory().
		Trusts(context.Background(), admodel.TrustQuery{BaseDN: InternalTopSystem})
	var native *admodel.LDAPError
	if !errors.As(err, &native) || native.Code != 4 || partial.Observation.Complete ||
		len(partial.Trusts) != 1 ||
		partial.Trusts[0].Raw.DistinguishedName != InternalTopTrust {
		t.Fatalf("partial page discarded: %+v %v", partial, err)
	}
}

func TestDirectoryDeadlineIncludesQueuedInitialRead(t *testing.T) {
	f := InternalNewTopologyFixture()
	client := f.InternalClient(30 * time.Millisecond)
	defer client.Close()
	<-adengine.InternalClientGate(client)
	defer func() { adengine.InternalClientGate(client) <- struct{}{} }()
	result, err := client.Directory().Forest(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) || result.Observation.Complete ||
		len(f.InternalDeadlines) != 0 ||
		len(f.InternalQueries) != 0 {
		t.Fatalf("queued budget: %v", err)
	}
}

func TestDirectoryRoleIdentitySurvivesHostFailure(t *testing.T) {
	f := InternalNewTopologyFixture()
	f.InternalFailBase = InternalTopServer
	f.InternalFailure = &admodel.LDAPError{Operation: "Search", Code: 50}
	client := f.InternalClient(time.Second)
	defer client.Close()
	domain, err := client.Directory().Domain(context.Background(), admodel.DomainOptions{})
	if err == nil || domain.Observation.Complete || domain.PDCEmulator == nil ||
		domain.PDCEmulator.NTDSSettingsDN != InternalTopDSA ||
		domain.PDCEmulator.ServerDN != InternalTopServer ||
		domain.PDCEmulator.HostName != nil {
		t.Fatalf("role identity lost: %+v %v", domain.PDCEmulator, err)
	}
}

func TestDirectoryMissingDefaultIsNotLDSInference(t *testing.T) {
	f := InternalNewTopologyFixture()
	delete(f.InternalRoot, "defaultnamingcontext")
	client := f.InternalClient(time.Second)
	defer client.Close()
	result, err := client.Directory().Domain(context.Background(), admodel.DomainOptions{})
	if !errors.Is(err, admodel.ErrIncompleteResult) ||
		errors.Is(err, admodel.ErrUnsupportedDirectory) ||
		result.Observation.RootDSE.Capabilities().Type != admodel.DirectoryADDS ||
		len(f.InternalQueries) != 0 {
		t.Fatalf("missing default/capability: %v", err)
	}
	delete(f.InternalRoot, "supportedcapabilities")
	_, err = client.Directory().Forest(context.Background())
	var capability *admodel.DirectoryCapabilityError
	if !errors.As(err, &capability) || capability.Actual != admodel.DirectoryUnknown ||
		len(f.InternalQueries) != 0 {
		t.Fatalf("unknown capability: %v", err)
	}
}

func TestDirectoryValidationAndLiteralEscaping(t *testing.T) {
	var client *adengine.Client
	if _, err := client.Directory().
		Trust(context.Background(), "", admodel.TrustOptions{}); !errors.Is(
		err,
		admodel.ErrInvalidDirectoryQuery,
	) {
		t.Fatal(err)
	}
	if _, err := client.Directory().
		Trusts(context.Background(), admodel.TrustQuery{BaseDN: "a", DomainDN: "b"}); !errors.Is(
		err,
		admodel.ErrInvalidDirectoryQuery,
	) {
		t.Fatal(err)
	}
	if _, err := client.Directory().
		Domain(context.Background(), admodel.DomainOptions{DistinguishedName: "a\x00b"}); !errors.Is(
		err,
		admodel.ErrInvalidDirectoryQuery,
	) {
		t.Fatal(err)
	}
	if _, err := client.Directory().
		Forest(context.Background()); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatal(err)
	}
	if got := admodel.InternalLdapLiteral("a*(b)\\\x00é"); got != "a\\2a\\28b\\29\\5c\\00é" {
		t.Fatalf("literal: %q", got)
	}
	if parent, err := admodel.InternalParentDirectoryDN(
		InternalTopServer,
	); err != nil ||
		parent != "CN=Servers,"+InternalTopSite {
		t.Fatalf("escaped parent: %s %v", parent, err)
	}
}
