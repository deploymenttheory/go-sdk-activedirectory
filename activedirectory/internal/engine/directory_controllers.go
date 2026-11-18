package engine

import (
	"context"
	"errors"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// DomainController reads one controller's server object, directory-service agent, and associated
// topology through the authenticated endpoint. An empty ServerDN selects the endpoint's own server;
// partial observations may accompany an error.
//
// Related cmdlet: Get-ADDomainController.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomaincontroller?view=windowsserver2025-ps
func (d *DirectoryService) DomainController(
	ctx context.Context,
	options admodel.DomainControllerOptions,
) (result admodel.DomainControllerResult, err error) {
	if !admodel.InternalValidDirectoryText(options.ServerDN) {
		return result, admodel.ErrInvalidDirectoryQuery
	}
	r, err := InternalDirectoryServiceBegin(d, ctx, "DomainController", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.InternalFinish(&result.Observation) }()
	if !r.InternalReady {
		return result, nil
	}
	serverDN := options.ServerDN
	if serverDN == "" {
		serverDN = r.InternalRequire(r.InternalObservation.RootDSE.ServerName, "serverName")
	}
	if serverDN == "" {
		return result, nil
	}
	// Validate the server identity before searching its DSA child.
	server := r.InternalOne(serverDN, "(objectClass=server)", admodel.InternalServerAttributes())
	if server.DistinguishedName == "" {
		return result, nil
	}
	dsas := r.InternalSearch(
		admodel.SearchOptions{
			Base:       server.DistinguishedName,
			Scope:      admodel.ScopeOneLevel,
			Filter:     "(objectClass=nTDSDSA)",
			Properties: admodel.InternalDsaAttributes(),
		},
	)
	if len(dsas.Objects) != 1 {
		if len(dsas.Objects) > 1 {
			r.InternalAdd(admodel.ErrInvalidResult)
		} else if dsas.Complete {
			r.InternalAdd(admodel.ErrDirectoryObjectNotFound)
		}
		return result, nil
	}
	result.Controller = r.InternalController(dsas.Objects[0], &server)
	return result, nil
}

// DomainControllers searches controller topology for the selected domain and optional site through the
// authenticated endpoint. Query selects domain, site, paging, and result limits; this is a directory
// read rather than a DC Locator call.
//
// Related cmdlet: Get-ADDomainController.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomaincontroller?view=windowsserver2025-ps
func (d *DirectoryService) DomainControllers(
	ctx context.Context,
	query admodel.DomainControllersQuery,
) (result admodel.DomainControllersResult, err error) {
	if !admodel.InternalValidDirectoryText(query.DomainDN) ||
		!admodel.InternalValidDirectoryText(query.SiteDN) {
		return result, admodel.ErrInvalidDirectoryQuery
	}
	if err := (admodel.SearchOptions{PageSize: query.PageSize, ResultLimit: query.ResultLimit}).Validate(); err != nil {
		return result, err
	}
	r, err := InternalDirectoryServiceBegin(d, ctx, "DomainControllers", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.InternalFinish(&result.Observation) }()
	if !r.InternalReady {
		return result, nil
	}
	domain := r.InternalSelectedDomain(query.DomainDN)
	configuration := r.InternalRequire(
		r.InternalObservation.RootDSE.ConfigurationNamingContext,
		"configurationNamingContext",
	)
	if domain == "" || configuration == "" {
		return result, nil
	}
	base := "CN=Sites," + configuration
	if query.SiteDN != "" {
		site := r.InternalOne(query.SiteDN, "(objectClass=site)", []string{"name"})
		if site.DistinguishedName == "" {
			return result, nil
		}
		base = "CN=Servers," + site.DistinguishedName
	}
	dsas := r.InternalSearch(
		admodel.SearchOptions{
			Base:  base,
			Scope: admodel.ScopeSubtree,
			Filter: "(&(objectClass=nTDSDSA)(msDS-HasDomainNCs=" + admodel.InternalLdapLiteral(
				domain,
			) + "))",
			Properties: admodel.InternalDsaAttributes(),
			PageSize:   query.PageSize,
		},
	)
	for _, dsa := range dsas.Objects {
		if err := context.Cause(r.InternalCtx); err != nil {
			r.InternalAdd(err)
			break
		}
		replica := r.InternalReplica(dsa, nil)
		if !r.InternalMatches(replica.IsGlobalCatalog, query.IsGlobalCatalog) ||
			!r.InternalMatches(replica.IsReadOnly, query.IsReadOnly) {
			continue
		}
		controller := r.InternalCompleteController(replica)
		result.Controllers = append(result.Controllers, controller)
		if query.ResultLimit > 0 && len(result.Controllers) == query.ResultLimit {
			result.LimitReached = true
			r.InternalObservation.Complete = false
			break
		}
	}
	return result, nil
}

func (r *InternalDirectoryRead) InternalMatches(actual, wanted *bool) bool {
	if wanted == nil {
		return true
	}
	if actual == nil {
		r.InternalAdd(admodel.ErrIncompleteResult)
		return false
	}
	return *actual == *wanted
}

func (r *InternalDirectoryRead) InternalReplicas(
	domain string,
	gcOnly bool,
) []admodel.ControllerReplica {
	configuration := r.InternalRequire(
		r.InternalObservation.RootDSE.ConfigurationNamingContext,
		"configurationNamingContext",
	)
	if configuration == "" {
		return nil
	}
	filter := "(objectClass=nTDSDSA)"
	if domain != "" {
		filter = "(&" + filter + "(msDS-HasDomainNCs=" + admodel.InternalLdapLiteral(domain) + "))"
	}
	if gcOnly {
		filter = "(&" + filter + "(options:1.2.840.113556.1.4.803:=1))"
	}
	search := r.InternalSearch(
		admodel.SearchOptions{
			Base:       "CN=Sites," + configuration,
			Scope:      admodel.ScopeSubtree,
			Filter:     filter,
			Properties: admodel.InternalDsaAttributes(),
		},
	)
	result := make([]admodel.ControllerReplica, 0, len(search.Objects))
	for _, dsa := range search.Objects {
		if err := context.Cause(r.InternalCtx); err != nil {
			r.InternalAdd(err)
			break
		}
		result = append(result, r.InternalReplica(dsa, nil))
	}
	return result
}

func (r *InternalDirectoryRead) InternalReplica(
	dsa admodel.Object,
	server *admodel.Object,
) admodel.ControllerReplica {
	result := admodel.ControllerReplica{Settings: dsa}
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: dsa.Attributes}
	result.DomainDN = decoder.InternalText("msDS-HasDomainNCs")
	result.Functionality = admodel.InternalDecodeScalar(
		&decoder,
		"msDS-Behavior-Version",
		admodel.InternalParseUint32,
	)
	category := decoder.InternalText("objectCategory")
	if options := admodel.InternalDecodeScalar(
		&decoder,
		"options",
		admodel.InternalParseDirectoryMask,
	); options != nil {
		value := *options&1 != 0
		result.IsGlobalCatalog = &value
	}
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	result.IsReadOnly = r.InternalReadOnlyCategory(category)
	if server != nil {
		result.Server = *server
	} else if parent := r.InternalParent(dsa.DistinguishedName); parent != "" {
		result.Server = r.InternalOne(
			parent,
			"(objectClass=server)",
			admodel.InternalServerAttributes(),
		)
	}
	decoder = admodel.InternalRootDSEDecoder{InternalAttributes: result.Server.Attributes}
	result.HostName = decoder.InternalText("dnsHostName")
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	return result
}

func (r *InternalDirectoryRead) InternalReadOnlyCategory(category *string) *bool {
	if category == nil {
		return nil
	}
	key := strings.ToLower(*category)
	if value, ok := r.InternalCategories[key]; ok {
		return value
	}
	raw := r.InternalOne(*category, "(objectClass=classSchema)", []string{"lDAPDisplayName"})
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
	name := decoder.InternalText("lDAPDisplayName")
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
			decoder.InternalInvalid("lDAPDisplayName")
		}
	}
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	r.InternalCategories[key] = result
	return result
}

func (r *InternalDirectoryRead) InternalController(
	dsa admodel.Object,
	server *admodel.Object,
) admodel.DomainController {
	return r.InternalCompleteController(r.InternalReplica(dsa, server))
}

func (r *InternalDirectoryRead) InternalCompleteController(
	replica admodel.ControllerReplica,
) admodel.DomainController {
	result := admodel.DomainController{ControllerReplica: replica}
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: replica.Settings.Attributes}
	result.NTDSSettingsObjectGUID = admodel.InternalCopiedBinary(&decoder, "objectGUID", 16)
	result.InvocationID = admodel.InternalCopiedBinary(&decoder, "invocationId", 16)
	result.Options = admodel.InternalDecodeScalar(
		&decoder,
		"options",
		admodel.InternalParseDirectoryMask,
	)
	for _, attribute := range []struct {
		InternalName string
		InternalKind admodel.ReplicaKind
	}{{"msDS-hasMasterNCs", admodel.ReplicaWritable}, {"msDS-hasFullReplicaNCs", admodel.ReplicaReadOnlyFull}, {"hasPartialReplicaNCs", admodel.ReplicaPartial}} {
		for _, dn := range decoder.InternalTexts(attribute.InternalName) {
			result.NamingContexts = append(
				result.NamingContexts,
				admodel.ReplicaNamingContext{DistinguishedName: dn, Kind: attribute.InternalKind},
			)
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
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	decoder = admodel.InternalRootDSEDecoder{InternalAttributes: replica.Server.Attributes}
	result.ServerObjectGUID = admodel.InternalCopiedBinary(&decoder, "objectGUID", 16)
	computerDN := decoder.InternalText("serverReference")
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	if dn := r.InternalRequire(computerDN, "serverReference"); dn != "" {
		result.Computer = r.InternalOne(
			dn,
			"(objectClass=computer)",
			[]string{
				"objectSid",
				"sAMAccountName",
				"userAccountControl",
				"operatingSystem",
				"operatingSystemVersion",
				"operatingSystemServicePack",
				"operatingSystemHotfix",
			},
		)
		decoder = admodel.InternalRootDSEDecoder{InternalAttributes: result.Computer.Attributes}
		result.ComputerObjectSID = admodel.InternalCopiedBinary(&decoder, "objectSid", 0)
		result.ComputerAccountName = decoder.InternalText("sAMAccountName")
		result.OperatingSystem = decoder.InternalText("operatingSystem")
		result.OperatingSystemVersion = decoder.InternalText("operatingSystemVersion")
		result.OperatingSystemServicePack = decoder.InternalText("operatingSystemServicePack")
		result.OperatingSystemHotfix = decoder.InternalText("operatingSystemHotfix")
		if flags := admodel.InternalDecodeScalar(
			&decoder,
			"userAccountControl",
			admodel.InternalParseDirectoryMask,
		); flags != nil {
			enabled := *flags&2 == 0
			result.Enabled = &enabled
		}
		r.InternalAdd(errors.Join(decoder.InternalErrors...))
	}
	if servers := r.InternalParent(replica.Server.DistinguishedName); servers != "" {
		if site := r.InternalParent(servers); site != "" {
			result.Site = r.InternalOne(site, "(objectClass=site)", []string{"name"})
			decoder = admodel.InternalRootDSEDecoder{InternalAttributes: result.Site.Attributes}
			result.SiteName = decoder.InternalText("name")
			r.InternalAdd(errors.Join(decoder.InternalErrors...))
		}
	}
	if dsa := r.InternalObservation.RootDSE.DSServiceName; dsa != nil &&
		strings.EqualFold(*dsa, replica.Settings.DistinguishedName) {
		result.GlobalCatalogReady = r.InternalObservation.RootDSE.IsGlobalCatalogReady
	}
	if replica.DomainDN != nil {
		r.InternalControllerRoles(&result, *replica.DomainDN)
	} else {
		r.InternalRequire(nil, "msDS-HasDomainNCs")
	}
	return result
}

func (r *InternalDirectoryRead) InternalControllerRoles(
	result *admodel.DomainController,
	domain string,
) {
	owners := make(map[admodel.FSMORole]*string)
	raw := r.InternalOne(
		domain,
		"(objectClass=domainDNS)",
		[]string{"fSMORoleOwner", "rIDManagerReference", "wellKnownObjects"},
	)
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
	owners[admodel.RolePDCEmulator] = decoder.InternalText("fSMORoleOwner")
	rid := decoder.InternalText("rIDManagerReference")
	containers := admodel.InternalWellKnownContainers(&decoder)
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	readOwner := func(base, filter string) *string {
		raw := r.InternalOne(base, filter, []string{"fSMORoleOwner"})
		decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
		owner := decoder.InternalText("fSMORoleOwner")
		r.InternalAdd(errors.Join(decoder.InternalErrors...))
		return owner
	}
	if rid != nil {
		owners[admodel.RoleRIDMaster] = readOwner(*rid, "(objectClass=rIDManager)")
	}
	if infrastructure := r.InternalContainer(
		containers,
		admodel.InternalWellKnownInfrastructure,
	); infrastructure != "" {
		owners[admodel.RoleInfrastructureMaster] = readOwner(
			infrastructure,
			"(objectClass=infrastructureUpdate)",
		)
	}
	if schema := r.InternalRequire(
		r.InternalObservation.RootDSE.SchemaNamingContext,
		"schemaNamingContext",
	); schema != "" {
		owners[admodel.RoleSchemaMaster] = readOwner(schema, "(objectClass=dMD)")
	}
	if configuration := r.InternalRequire(
		r.InternalObservation.RootDSE.ConfigurationNamingContext,
		"configurationNamingContext",
	); configuration != "" {
		owners[admodel.RoleDomainNamingMaster] = readOwner(
			"CN=Partitions,"+configuration,
			"(objectClass=crossRefContainer)",
		)
	}
	result.OperationMasterRolesKnown = true
	for _, role := range []admodel.FSMORole{
		admodel.RolePDCEmulator,
		admodel.RoleRIDMaster,
		admodel.RoleInfrastructureMaster,
		admodel.RoleSchemaMaster,
		admodel.RoleDomainNamingMaster,
	} {
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
