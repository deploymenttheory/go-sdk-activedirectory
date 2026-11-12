package activedirectory

import (
	"context"
	"errors"
	"strings"
)

// DomainOptions selects an explicit domain NC or the configured/default NC.
// Other identity forms will use the shared identity resolver when available.
type DomainOptions struct{ DistinguishedName string }

// RoleOwner preserves the role's DSA identity even when its host read fails.
// Holding a role does not establish availability of that server.
type RoleOwner struct {
	NTDSSettingsDN string
	ServerDN       string
	HostName       *string
}

// CrossReference retains flags and enabled state without guessing the intent of
// disabled or external references. Linked names are distinguished names.
type CrossReference struct {
	Raw           Object
	NamingContext *string
	DNSRoot       *string
	NetBIOSName   *string
	SystemFlags   *uint32
	Enabled       *bool
	TrustParent   *string
	RootTrust     *string
}

type Domain struct {
	Observation           DirectoryObservation
	Raw                   Object
	ObjectGUID            []byte
	ObjectSID             []byte
	Name                  *string
	DNSRoot               *string
	NetBIOSName           *string
	ForestDNSRoot         *string
	FunctionalLevel       *uint32
	AllowedDNSSuffixes    []string
	LogonTimeSyncInterval *uint32
	ManagedBy             *string
	GroupPolicyLinks      *string
	SubordinateReferences []string
	WellKnownContainers   map[string]string
	CrossReference        *CrossReference
	Parent                *CrossReference
	Children              []CrossReference
	PDCEmulator           *RoleOwner
	RIDMaster             *RoleOwner
	InfrastructureMaster  *RoleOwner
	Replicas              []ControllerReplica
}

// Domain reads one domain NC, its cross-reference/topology and three role owners.
// Nil fields retain unavailable values. A non-nil error may accompany useful
// values and raw objects; no other endpoint is contacted for an unreadable link.
func (d *DirectoryService) Domain(ctx context.Context, options DomainOptions) (result Domain, err error) {
	if !validDirectoryText(options.DistinguishedName) {
		return result, ErrInvalidDirectoryQuery
	}
	r, err := d.begin(ctx, "Domain", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.finish(&result.Observation) }()
	if !r.ready {
		return result, nil
	}
	base := r.selectedDomain(options.DistinguishedName)
	result.Raw = r.one(base, "(objectClass=domainDNS)", domainAttributes())
	if result.Raw.DistinguishedName == "" {
		return result, nil
	}
	decoder := rootDSEDecoder{attributes: result.Raw.Attributes}
	result.ObjectGUID = copiedBinary(&decoder, "objectGUID", 16)
	result.ObjectSID = copiedBinary(&decoder, "objectSid", 0)
	result.Name = decoder.text("name")
	result.FunctionalLevel = decodeScalar(&decoder, "msDS-Behavior-Version", parseUint32)
	result.AllowedDNSSuffixes = decoder.texts("msDS-AllowedDNSSuffixes")
	result.LogonTimeSyncInterval = decodeScalar(&decoder, "msDS-LogonTimeSyncInterval", parseUint32)
	result.ManagedBy = decoder.text("managedBy")
	result.GroupPolicyLinks = decoder.text("gpLink")
	result.SubordinateReferences = decoder.texts("subRefs")
	result.WellKnownContainers = wellKnownContainers(&decoder)
	pdc, rid := decoder.text("fSMORoleOwner"), decoder.text("rIDManagerReference")
	r.add(errors.Join(decoder.errors...))
	refs := r.crossReferences()
	result.CrossReference = r.crossRefForNC(refs, result.Raw.DistinguishedName)
	if result.CrossReference != nil {
		result.DNSRoot, result.NetBIOSName = result.CrossReference.DNSRoot, result.CrossReference.NetBIOSName
		for i := range refs {
			ref := &refs[i]
			if result.CrossReference.TrustParent != nil && strings.EqualFold(*result.CrossReference.TrustParent, ref.Raw.DistinguishedName) {
				result.Parent = ref
			}
			if ref.TrustParent != nil && strings.EqualFold(*ref.TrustParent, result.CrossReference.Raw.DistinguishedName) {
				result.Children = append(result.Children, *ref)
			}
		}
		if result.CrossReference.TrustParent != nil && result.Parent == nil {
			r.add(ErrIncompleteResult)
		}
	}
	if root := r.observation.RootDSE.RootDomainNamingContext; root != nil {
		if ref := r.crossRefForNC(refs, *root); ref != nil {
			result.ForestDNSRoot = ref.DNSRoot
		}
	} else {
		r.require(nil, "rootDomainNamingContext")
	}
	result.PDCEmulator = r.roleOwner(pdc)
	if rid != nil {
		result.RIDMaster = r.roleOn(*rid, "(objectClass=rIDManager)")
	}
	if infrastructure := r.container(result.WellKnownContainers, wellKnownInfrastructure); infrastructure != "" {
		result.InfrastructureMaster = r.roleOn(infrastructure, "(objectClass=infrastructureUpdate)")
	}
	result.Replicas = r.replicas(result.Raw.DistinguishedName, false)
	return result, nil
}

func domainAttributes() []string {
	return []string{"objectGUID", "objectSid", "name", "msDS-Behavior-Version", "msDS-AllowedDNSSuffixes", "msDS-LogonTimeSyncInterval", "managedBy", "gpLink", "subRefs", "wellKnownObjects", "rIDManagerReference", "fSMORoleOwner"}
}

func crossReferenceAttributes() []string {
	return []string{"objectGUID", "nCName", "dnsRoot", "nETBIOSName", "systemFlags", "enabled", "trustParent", "rootTrust"}
}

func (r *directoryRead) crossReferences() []CrossReference {
	configuration := r.require(r.observation.RootDSE.ConfigurationNamingContext, "configurationNamingContext")
	if configuration == "" {
		return nil
	}
	search := r.search(SearchOptions{Base: "CN=Partitions," + configuration, Scope: ScopeOneLevel, Filter: "(objectClass=crossRef)", Properties: crossReferenceAttributes()})
	refs := make([]CrossReference, 0, len(search.Objects))
	for _, raw := range search.Objects {
		decoder := rootDSEDecoder{attributes: raw.Attributes}
		ref := CrossReference{Raw: raw, NamingContext: decoder.text("nCName"), DNSRoot: decoder.text("dnsRoot"), NetBIOSName: decoder.text("nETBIOSName"), TrustParent: decoder.text("trustParent"), RootTrust: decoder.text("rootTrust")}
		ref.SystemFlags = decodeScalar(&decoder, "systemFlags", parseDirectoryMask)
		ref.Enabled = decodeScalar(&decoder, "enabled", parseLDAPBool)
		r.add(errors.Join(decoder.errors...))
		refs = append(refs, ref)
	}
	return refs
}

func (r *directoryRead) crossRefForNC(refs []CrossReference, nc string) *CrossReference {
	var found *CrossReference
	for i := range refs {
		if refs[i].NamingContext != nil && strings.EqualFold(*refs[i].NamingContext, nc) {
			if found != nil {
				r.add(ErrInvalidResult)
				return nil
			}
			found = &refs[i]
		}
	}
	if found == nil {
		r.add(ErrIncompleteResult)
	}
	return found
}

func (r *directoryRead) roleOn(base, filter string) *RoleOwner {
	raw := r.one(base, filter, []string{"fSMORoleOwner"})
	decoder := rootDSEDecoder{attributes: raw.Attributes}
	owner := decoder.text("fSMORoleOwner")
	r.add(errors.Join(decoder.errors...))
	return r.roleOwner(owner)
}

func (r *directoryRead) roleOwner(dsa *string) *RoleOwner {
	if dsa == nil {
		return nil
	}
	result := &RoleOwner{NTDSSettingsDN: *dsa}
	result.ServerDN = r.parent(*dsa)
	if result.ServerDN == "" {
		return result
	}
	server := r.one(result.ServerDN, "(objectClass=server)", []string{"dnsHostName"})
	decoder := rootDSEDecoder{attributes: server.Attributes}
	result.HostName = decoder.text("dnsHostName")
	r.add(errors.Join(decoder.errors...))
	return result
}

type ForestSite struct {
	Raw  Object
	Name *string
}

// Forest classifies cross-references by their raw systemFlags. Disabled entries
// remain visible with Enabled state; these lists are directory observations,
// not a promise that every naming context is online or reachable.
type Forest struct {
	Observation           DirectoryObservation
	RootDomainDN          *string
	Name                  *string
	FunctionalLevel       *uint32
	UPNSuffixes           []string
	SPNSuffixes           []string
	CrossReferences       []CrossReference
	Domains               []CrossReference
	ApplicationPartitions []CrossReference
	ExternalReferences    []CrossReference
	Sites                 []ForestSite
	GlobalCatalogs        []ControllerReplica
	DomainNamingMaster    *RoleOwner
	SchemaMaster          *RoleOwner
}

// Forest reads topology for the connected server's forest. It does not follow
// trust relationships or discover a server for another forest identity.
func (d *DirectoryService) Forest(ctx context.Context) (result Forest, err error) {
	r, err := d.begin(ctx, "Forest", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.finish(&result.Observation) }()
	if !r.ready {
		return result, nil
	}
	root := &r.observation.RootDSE
	result.RootDomainDN = root.RootDomainNamingContext
	configuration := r.require(root.ConfigurationNamingContext, "configurationNamingContext")
	schema := r.require(root.SchemaNamingContext, "schemaNamingContext")
	if configuration == "" || schema == "" {
		return result, nil
	}
	partitions := r.one("CN=Partitions,"+configuration, "(objectClass=crossRefContainer)", []string{"msDS-Behavior-Version", "uPNSuffixes", "msDS-SPNSuffixes", "fSMORoleOwner"})
	decoder := rootDSEDecoder{attributes: partitions.Attributes}
	result.FunctionalLevel = decodeScalar(&decoder, "msDS-Behavior-Version", parseUint32)
	result.UPNSuffixes = decoder.texts("uPNSuffixes")
	result.SPNSuffixes = decoder.texts("msDS-SPNSuffixes")
	namingMaster := decoder.text("fSMORoleOwner")
	r.add(errors.Join(decoder.errors...))
	result.CrossReferences = r.crossReferences()
	for _, ref := range result.CrossReferences {
		if ref.SystemFlags == nil {
			r.add(ErrIncompleteResult)
			continue
		}
		switch {
		case *ref.SystemFlags&3 == 3:
			result.Domains = append(result.Domains, ref)
		case *ref.SystemFlags&1 == 0:
			result.ExternalReferences = append(result.ExternalReferences, ref)
		case ref.NamingContext != nil && !strings.EqualFold(*ref.NamingContext, configuration) && !strings.EqualFold(*ref.NamingContext, schema):
			result.ApplicationPartitions = append(result.ApplicationPartitions, ref)
		}
	}
	if domain := r.require(result.RootDomainDN, "rootDomainNamingContext"); domain != "" {
		if ref := r.crossRefForNC(result.CrossReferences, domain); ref != nil {
			result.Name = ref.DNSRoot
		}
	}
	sites := r.search(SearchOptions{Base: "CN=Sites," + configuration, Scope: ScopeOneLevel, Filter: "(objectClass=site)", Properties: []string{"name"}})
	for _, raw := range sites.Objects {
		decoder := rootDSEDecoder{attributes: raw.Attributes}
		result.Sites = append(result.Sites, ForestSite{Raw: raw, Name: decoder.text("name")})
		r.add(errors.Join(decoder.errors...))
	}
	result.GlobalCatalogs = r.replicas("", true)
	result.DomainNamingMaster = r.roleOwner(namingMaster)
	result.SchemaMaster = r.roleOn(schema, "(objectClass=dMD)")
	return result, nil
}
