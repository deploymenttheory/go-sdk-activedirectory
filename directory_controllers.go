package activedirectory

import (
	"context"
	"errors"
	"strings"
)

// ControllerReplica separates configured GC state from the live endpoint's GC
// readiness. ReadOnly is nil when the category cannot be determined.
type ControllerReplica struct {
	Settings        Object
	Server          Object
	HostName        *string
	DomainDN        *string
	IsReadOnly      *bool
	IsGlobalCatalog *bool
	Functionality   *uint32
}

type ReplicaKind uint8

const (
	ReplicaWritable ReplicaKind = iota + 1
	ReplicaReadOnlyFull
	ReplicaPartial
)

type ReplicaNamingContext struct {
	DistinguishedName string
	Kind              ReplicaKind
}

type FSMORole string

const (
	RolePDCEmulator          FSMORole = "PDCEmulator"
	RoleRIDMaster            FSMORole = "RIDMaster"
	RoleInfrastructureMaster FSMORole = "InfrastructureMaster"
	RoleSchemaMaster         FSMORole = "SchemaMaster"
	RoleDomainNamingMaster   FSMORole = "DomainNamingMaster"
)

type DomainController struct {
	ControllerReplica
	Computer                   Object
	Site                       Object
	SiteName                   *string
	ServerObjectGUID           []byte
	NTDSSettingsObjectGUID     []byte
	InvocationID               []byte
	ComputerObjectSID          []byte
	ComputerAccountName        *string
	Enabled                    *bool
	OperatingSystem            *string
	OperatingSystemVersion     *string
	OperatingSystemServicePack *string
	OperatingSystemHotfix      *string
	Options                    *uint32
	NamingContexts             []ReplicaNamingContext
	Partitions                 []string
	OperationMasterRoles       []FSMORole
	OperationMasterRolesKnown  bool
	// Only populated for the connected endpoint's own DSA.
	GlobalCatalogReady *bool
}

type DomainControllerResult struct {
	Observation DirectoryObservation
	Controller  DomainController
}
type DomainControllersResult struct {
	Observation  DirectoryObservation
	Controllers  []DomainController
	LimitReached bool
}

// DomainControllerOptions selects a server object's DN. Empty selects the
// authenticated endpoint's serverName. Host/IP/GUID/computer/DSA identities need
// the shared identity resolver and are deliberately not guessed from strings.
type DomainControllerOptions struct{ ServerDN string }

// DomainControllersQuery offers explicit joined criteria. It is not the
// PowerShell Filter language. General expressions will use the shared compiler.
// DomainDN defaults to the configured/default NC; Sites spans a forest, so the
// query always constrains msDS-HasDomainNCs as well as any site selection.
type DomainControllersQuery struct {
	DomainDN        string
	SiteDN          string
	IsGlobalCatalog *bool
	IsReadOnly      *bool
	PageSize        int
	ResultLimit     int
}

func (d *DirectoryService) DomainController(ctx context.Context, options DomainControllerOptions) (result DomainControllerResult, err error) {
	if !validDirectoryText(options.ServerDN) {
		return result, ErrInvalidDirectoryQuery
	}
	r, err := d.begin(ctx, "DomainController", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.finish(&result.Observation) }()
	if !r.ready {
		return result, nil
	}
	serverDN := options.ServerDN
	if serverDN == "" {
		serverDN = r.require(r.observation.RootDSE.ServerName, "serverName")
	}
	if serverDN == "" {
		return result, nil
	}
	// Validate the server identity before searching its DSA child.
	server := r.one(serverDN, "(objectClass=server)", serverAttributes())
	if server.DistinguishedName == "" {
		return result, nil
	}
	dsas := r.search(SearchOptions{Base: server.DistinguishedName, Scope: ScopeOneLevel, Filter: "(objectClass=nTDSDSA)", Properties: dsaAttributes()})
	if len(dsas.Objects) != 1 {
		if len(dsas.Objects) > 1 {
			r.add(ErrInvalidResult)
		} else if dsas.Complete {
			r.add(ErrDirectoryObjectNotFound)
		}
		return result, nil
	}
	result.Controller = r.controller(dsas.Objects[0], &server)
	return result, nil
}

func (d *DirectoryService) DomainControllers(ctx context.Context, query DomainControllersQuery) (result DomainControllersResult, err error) {
	if !validDirectoryText(query.DomainDN) || !validDirectoryText(query.SiteDN) {
		return result, ErrInvalidDirectoryQuery
	}
	if err := (SearchOptions{PageSize: query.PageSize, ResultLimit: query.ResultLimit}).Validate(); err != nil {
		return result, err
	}
	r, err := d.begin(ctx, "DomainControllers", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.finish(&result.Observation) }()
	if !r.ready {
		return result, nil
	}
	domain := r.selectedDomain(query.DomainDN)
	configuration := r.require(r.observation.RootDSE.ConfigurationNamingContext, "configurationNamingContext")
	if domain == "" || configuration == "" {
		return result, nil
	}
	base := "CN=Sites," + configuration
	if query.SiteDN != "" {
		site := r.one(query.SiteDN, "(objectClass=site)", []string{"name"})
		if site.DistinguishedName == "" {
			return result, nil
		}
		base = "CN=Servers," + site.DistinguishedName
	}
	dsas := r.search(SearchOptions{Base: base, Scope: ScopeSubtree, Filter: "(&(objectClass=nTDSDSA)(msDS-HasDomainNCs=" + ldapLiteral(domain) + "))", Properties: dsaAttributes(), PageSize: query.PageSize})
	for _, dsa := range dsas.Objects {
		if err := context.Cause(r.ctx); err != nil {
			r.add(err)
			break
		}
		replica := r.replica(dsa, nil)
		if !r.matches(replica.IsGlobalCatalog, query.IsGlobalCatalog) || !r.matches(replica.IsReadOnly, query.IsReadOnly) {
			continue
		}
		controller := r.completeController(replica)
		result.Controllers = append(result.Controllers, controller)
		if query.ResultLimit > 0 && len(result.Controllers) == query.ResultLimit {
			result.LimitReached = true
			r.observation.Complete = false
			break
		}
	}
	return result, nil
}

func (r *directoryRead) matches(actual, wanted *bool) bool {
	if wanted == nil {
		return true
	}
	if actual == nil {
		r.add(ErrIncompleteResult)
		return false
	}
	return *actual == *wanted
}

func serverAttributes() []string { return []string{"objectGUID", "dnsHostName", "serverReference"} }
func dsaAttributes() []string {
	return []string{"objectGUID", "invocationId", "objectCategory", "options", "msDS-Behavior-Version", "msDS-HasDomainNCs", "msDS-hasMasterNCs", "msDS-hasFullReplicaNCs", "hasPartialReplicaNCs"}
}

func (r *directoryRead) replicas(domain string, gcOnly bool) []ControllerReplica {
	configuration := r.require(r.observation.RootDSE.ConfigurationNamingContext, "configurationNamingContext")
	if configuration == "" {
		return nil
	}
	filter := "(objectClass=nTDSDSA)"
	if domain != "" {
		filter = "(&" + filter + "(msDS-HasDomainNCs=" + ldapLiteral(domain) + "))"
	}
	if gcOnly {
		filter = "(&" + filter + "(options:1.2.840.113556.1.4.803:=1))"
	}
	search := r.search(SearchOptions{Base: "CN=Sites," + configuration, Scope: ScopeSubtree, Filter: filter, Properties: dsaAttributes()})
	result := make([]ControllerReplica, 0, len(search.Objects))
	for _, dsa := range search.Objects {
		if err := context.Cause(r.ctx); err != nil {
			r.add(err)
			break
		}
		result = append(result, r.replica(dsa, nil))
	}
	return result
}

func (r *directoryRead) replica(dsa Object, server *Object) ControllerReplica {
	result := ControllerReplica{Settings: dsa}
	decoder := rootDSEDecoder{attributes: dsa.Attributes}
	result.DomainDN = decoder.text("msDS-HasDomainNCs")
	result.Functionality = decodeScalar(&decoder, "msDS-Behavior-Version", parseUint32)
	category := decoder.text("objectCategory")
	if options := decodeScalar(&decoder, "options", parseDirectoryMask); options != nil {
		value := *options&1 != 0
		result.IsGlobalCatalog = &value
	}
	r.add(errors.Join(decoder.errors...))
	result.IsReadOnly = r.readOnlyCategory(category)
	if server != nil {
		result.Server = *server
	} else if parent := r.parent(dsa.DistinguishedName); parent != "" {
		result.Server = r.one(parent, "(objectClass=server)", serverAttributes())
	}
	decoder = rootDSEDecoder{attributes: result.Server.Attributes}
	result.HostName = decoder.text("dnsHostName")
	r.add(errors.Join(decoder.errors...))
	return result
}

func (r *directoryRead) readOnlyCategory(category *string) *bool {
	if category == nil {
		return nil
	}
	key := strings.ToLower(*category)
	if value, ok := r.categories[key]; ok {
		return value
	}
	raw := r.one(*category, "(objectClass=classSchema)", []string{"lDAPDisplayName"})
	decoder := rootDSEDecoder{attributes: raw.Attributes}
	name := decoder.text("lDAPDisplayName")
	var result *bool
	if name != nil {
		switch {
		case strings.EqualFold(*name, "nTDSDSARO"):
			value := true
			result = &value
		case strings.EqualFold(*name, "nTDSDSA"):
			value := false
			result = &value
		default:
			decoder.invalid("lDAPDisplayName")
		}
	}
	r.add(errors.Join(decoder.errors...))
	r.categories[key] = result
	return result
}

func (r *directoryRead) controller(dsa Object, server *Object) DomainController {
	return r.completeController(r.replica(dsa, server))
}

func (r *directoryRead) completeController(replica ControllerReplica) DomainController {
	result := DomainController{ControllerReplica: replica}
	decoder := rootDSEDecoder{attributes: replica.Settings.Attributes}
	result.NTDSSettingsObjectGUID = copiedBinary(&decoder, "objectGUID", 16)
	result.InvocationID = copiedBinary(&decoder, "invocationId", 16)
	result.Options = decodeScalar(&decoder, "options", parseDirectoryMask)
	for _, attribute := range []struct {
		name string
		kind ReplicaKind
	}{{"msDS-hasMasterNCs", ReplicaWritable}, {"msDS-hasFullReplicaNCs", ReplicaReadOnlyFull}, {"hasPartialReplicaNCs", ReplicaPartial}} {
		for _, dn := range decoder.texts(attribute.name) {
			result.NamingContexts = append(result.NamingContexts, ReplicaNamingContext{DistinguishedName: dn, Kind: attribute.kind})
			found := false
			for _, previous := range result.Partitions {
				if strings.EqualFold(previous, dn) {
					found = true
					break
				}
			}
			if !found {
				result.Partitions = append(result.Partitions, dn)
			}
		}
	}
	r.add(errors.Join(decoder.errors...))
	decoder = rootDSEDecoder{attributes: replica.Server.Attributes}
	result.ServerObjectGUID = copiedBinary(&decoder, "objectGUID", 16)
	computerDN := decoder.text("serverReference")
	r.add(errors.Join(decoder.errors...))
	if dn := r.require(computerDN, "serverReference"); dn != "" {
		result.Computer = r.one(dn, "(objectClass=computer)", []string{"objectSid", "sAMAccountName", "userAccountControl", "operatingSystem", "operatingSystemVersion", "operatingSystemServicePack", "operatingSystemHotfix"})
		decoder = rootDSEDecoder{attributes: result.Computer.Attributes}
		result.ComputerObjectSID = copiedBinary(&decoder, "objectSid", 0)
		result.ComputerAccountName = decoder.text("sAMAccountName")
		result.OperatingSystem = decoder.text("operatingSystem")
		result.OperatingSystemVersion = decoder.text("operatingSystemVersion")
		result.OperatingSystemServicePack = decoder.text("operatingSystemServicePack")
		result.OperatingSystemHotfix = decoder.text("operatingSystemHotfix")
		if flags := decodeScalar(&decoder, "userAccountControl", parseDirectoryMask); flags != nil {
			enabled := *flags&2 == 0
			result.Enabled = &enabled
		}
		r.add(errors.Join(decoder.errors...))
	}
	if servers := r.parent(replica.Server.DistinguishedName); servers != "" {
		if site := r.parent(servers); site != "" {
			result.Site = r.one(site, "(objectClass=site)", []string{"name"})
			decoder = rootDSEDecoder{attributes: result.Site.Attributes}
			result.SiteName = decoder.text("name")
			r.add(errors.Join(decoder.errors...))
		}
	}
	if dsa := r.observation.RootDSE.DSServiceName; dsa != nil && strings.EqualFold(*dsa, replica.Settings.DistinguishedName) {
		result.GlobalCatalogReady = r.observation.RootDSE.IsGlobalCatalogReady
	}
	if replica.DomainDN != nil {
		r.controllerRoles(&result, *replica.DomainDN)
	} else {
		r.require(nil, "msDS-HasDomainNCs")
	}
	return result
}

func (r *directoryRead) controllerRoles(result *DomainController, domain string) {
	owners := make(map[FSMORole]*string)
	raw := r.one(domain, "(objectClass=domainDNS)", []string{"fSMORoleOwner", "rIDManagerReference", "wellKnownObjects"})
	decoder := rootDSEDecoder{attributes: raw.Attributes}
	owners[RolePDCEmulator] = decoder.text("fSMORoleOwner")
	rid := decoder.text("rIDManagerReference")
	containers := wellKnownContainers(&decoder)
	r.add(errors.Join(decoder.errors...))
	readOwner := func(base, filter string) *string {
		raw := r.one(base, filter, []string{"fSMORoleOwner"})
		decoder := rootDSEDecoder{attributes: raw.Attributes}
		owner := decoder.text("fSMORoleOwner")
		r.add(errors.Join(decoder.errors...))
		return owner
	}
	if rid != nil {
		owners[RoleRIDMaster] = readOwner(*rid, "(objectClass=rIDManager)")
	}
	if infrastructure := r.container(containers, wellKnownInfrastructure); infrastructure != "" {
		owners[RoleInfrastructureMaster] = readOwner(infrastructure, "(objectClass=infrastructureUpdate)")
	}
	if schema := r.require(r.observation.RootDSE.SchemaNamingContext, "schemaNamingContext"); schema != "" {
		owners[RoleSchemaMaster] = readOwner(schema, "(objectClass=dMD)")
	}
	if configuration := r.require(r.observation.RootDSE.ConfigurationNamingContext, "configurationNamingContext"); configuration != "" {
		owners[RoleDomainNamingMaster] = readOwner("CN=Partitions,"+configuration, "(objectClass=crossRefContainer)")
	}
	result.OperationMasterRolesKnown = true
	for _, role := range []FSMORole{RolePDCEmulator, RoleRIDMaster, RoleInfrastructureMaster, RoleSchemaMaster, RoleDomainNamingMaster} {
		owner := owners[role]
		if owner == nil || *owner == "" {
			result.OperationMasterRolesKnown = false
			continue
		}
		if strings.EqualFold(*owner, result.Settings.DistinguishedName) {
			result.OperationMasterRoles = append(result.OperationMasterRoles, role)
		}
	}
}
