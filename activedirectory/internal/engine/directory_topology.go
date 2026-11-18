package engine

import (
	"context"
	"errors"
	"strings"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Domain reads one domain NC, its cross-reference/topology and three role owners.
// Nil fields retain unavailable values. A non-nil error may accompany useful
// values and raw objects; no other endpoint is contacted for an unreadable link.
//
// Related cmdlet: Get-ADDomain.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addomain?view=windowsserver2025-ps
func (d *DirectoryService) Domain(
	ctx context.Context,
	options admodel.DomainOptions,
) (result admodel.Domain, err error) {
	if !admodel.InternalValidDirectoryText(options.DistinguishedName) {
		return result, admodel.ErrInvalidDirectoryQuery
	}
	r, err := InternalDirectoryServiceBegin(d, ctx, "Domain", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.InternalFinish(&result.Observation) }()
	if !r.InternalReady {
		return result, nil
	}
	base := r.InternalSelectedDomain(options.DistinguishedName)
	result.Raw = r.InternalOne(base, "(objectClass=domainDNS)", admodel.InternalDomainAttributes())
	if result.Raw.DistinguishedName == "" {
		return result, nil
	}
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: result.Raw.Attributes}
	result.ObjectGUID = admodel.InternalCopiedBinary(&decoder, "objectGUID", 16)
	result.ObjectSID = admodel.InternalCopiedBinary(&decoder, "objectSid", 0)
	result.Name = decoder.InternalText("name")
	result.FunctionalLevel = admodel.InternalDecodeScalar(
		&decoder,
		"msDS-Behavior-Version",
		admodel.InternalParseUint32,
	)
	result.AllowedDNSSuffixes = decoder.InternalTexts("msDS-AllowedDNSSuffixes")
	result.LogonTimeSyncInterval = admodel.InternalDecodeScalar(
		&decoder,
		"msDS-LogonTimeSyncInterval",
		admodel.InternalParseUint32,
	)
	result.ManagedBy = decoder.InternalText("managedBy")
	result.PublicKeyRequiredPasswordRolling = admodel.InternalDecodeScalar(
		&decoder,
		"msDS-ExpirePasswordsOnSmartCardOnlyAccounts",
		admodel.InternalParseLDAPBool,
	)
	result.GroupPolicyLinks = decoder.InternalText("gpLink")
	result.SubordinateReferences = decoder.InternalTexts("subRefs")
	result.WellKnownContainers = admodel.InternalWellKnownContainers(&decoder)
	pdc, rid := decoder.InternalText("fSMORoleOwner"), decoder.InternalText("rIDManagerReference")
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	refs := r.InternalCrossReferences()
	result.CrossReference = r.InternalCrossRefForNC(refs, result.Raw.DistinguishedName)
	if result.CrossReference != nil {
		result.DNSRoot, result.NetBIOSName = result.CrossReference.DNSRoot, result.CrossReference.NetBIOSName
		for i := range refs {
			ref := &refs[i]
			if result.CrossReference.TrustParent != nil &&
				strings.EqualFold(*result.CrossReference.TrustParent, ref.Raw.DistinguishedName) {
				result.Parent = ref
			}
			if ref.TrustParent != nil &&
				strings.EqualFold(*ref.TrustParent, result.CrossReference.Raw.DistinguishedName) {
				result.Children = append(result.Children, *ref)
			}
		}
		if result.CrossReference.TrustParent != nil && result.Parent == nil {
			r.InternalAdd(admodel.ErrIncompleteResult)
		}
	}
	if root := r.InternalObservation.RootDSE.RootDomainNamingContext; root != nil {
		if ref := r.InternalCrossRefForNC(refs, *root); ref != nil {
			result.ForestDNSRoot = ref.DNSRoot
		}
	} else {
		r.InternalRequire(nil, "rootDomainNamingContext")
	}
	result.PDCEmulator = r.InternalRoleOwner(pdc)
	if rid != nil {
		result.RIDMaster = r.InternalRoleOn(*rid, "(objectClass=rIDManager)")
	}
	if infrastructure := r.InternalContainer(
		result.WellKnownContainers,
		admodel.InternalWellKnownInfrastructure,
	); infrastructure != "" {
		result.InfrastructureMaster = r.InternalRoleOn(
			infrastructure,
			"(objectClass=infrastructureUpdate)",
		)
	}
	result.Replicas = r.InternalReplicas(result.Raw.DistinguishedName, false)
	return result, nil
}

func (r *InternalDirectoryRead) InternalCrossReferences() []admodel.CrossReference {
	configuration := r.InternalRequire(
		r.InternalObservation.RootDSE.ConfigurationNamingContext,
		"configurationNamingContext",
	)
	if configuration == "" {
		return nil
	}
	search := r.InternalSearch(
		admodel.SearchOptions{
			Base:       "CN=Partitions," + configuration,
			Scope:      admodel.ScopeOneLevel,
			Filter:     "(objectClass=crossRef)",
			Properties: admodel.InternalCrossReferenceAttributes(),
		},
	)
	refs := make([]admodel.CrossReference, 0, len(search.Objects))
	for _, raw := range search.Objects {
		decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
		ref := admodel.CrossReference{
			Raw:           raw,
			NamingContext: decoder.InternalText("nCName"),
			DNSRoot:       decoder.InternalText("dnsRoot"),
			NetBIOSName:   decoder.InternalText("nETBIOSName"),
			TrustParent:   decoder.InternalText("trustParent"),
			RootTrust:     decoder.InternalText("rootTrust"),
		}
		ref.SystemFlags = admodel.InternalDecodeScalar(
			&decoder,
			"systemFlags",
			admodel.InternalParseDirectoryMask,
		)
		ref.Enabled = admodel.InternalDecodeScalar(
			&decoder,
			"enabled",
			admodel.InternalParseLDAPBool,
		)
		r.InternalAdd(errors.Join(decoder.InternalErrors...))
		refs = append(refs, ref)
	}
	return refs
}

func (r *InternalDirectoryRead) InternalCrossRefForNC(
	refs []admodel.CrossReference,
	nc string,
) *admodel.CrossReference {
	var found *admodel.CrossReference
	for i := range refs {
		if refs[i].NamingContext != nil && strings.EqualFold(*refs[i].NamingContext, nc) {
			if found != nil {
				r.InternalAdd(admodel.ErrInvalidResult)
				return nil
			}
			found = &refs[i]
		}
	}
	if found == nil {
		r.InternalAdd(admodel.ErrIncompleteResult)
	}
	return found
}

func (r *InternalDirectoryRead) InternalRoleOn(base, filter string) *admodel.RoleOwner {
	raw := r.InternalOne(base, filter, []string{"fSMORoleOwner"})
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
	owner := decoder.InternalText("fSMORoleOwner")
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	return r.InternalRoleOwner(owner)
}

func (r *InternalDirectoryRead) InternalRoleOwner(dsa *string) *admodel.RoleOwner {
	if dsa == nil {
		return nil
	}
	result := &admodel.RoleOwner{NTDSSettingsDN: *dsa}
	result.ServerDN = r.InternalParent(*dsa)
	if result.ServerDN == "" {
		return result
	}
	server := r.InternalOne(result.ServerDN, "(objectClass=server)", []string{"dnsHostName"})
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: server.Attributes}
	result.HostName = decoder.InternalText("dnsHostName")
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	return result
}

// Forest reads topology for the connected server's forest. It does not follow
// trust relationships or discover a server for another forest identity.
//
// Related cmdlet: Get-ADForest.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adforest?view=windowsserver2025-ps
func (d *DirectoryService) Forest(ctx context.Context) (result admodel.Forest, err error) {
	r, err := InternalDirectoryServiceBegin(d, ctx, "Forest", true)
	if err != nil {
		return result, err
	}
	defer func() { err = r.InternalFinish(&result.Observation) }()
	if !r.InternalReady {
		return result, nil
	}
	root := &r.InternalObservation.RootDSE
	result.RootDomainDN = root.RootDomainNamingContext
	configuration := r.InternalRequire(
		root.ConfigurationNamingContext,
		"configurationNamingContext",
	)
	schema := r.InternalRequire(root.SchemaNamingContext, "schemaNamingContext")
	if configuration == "" || schema == "" {
		return result, nil
	}
	partitions := r.InternalOne(
		"CN=Partitions,"+configuration,
		"(objectClass=crossRefContainer)",
		[]string{"msDS-Behavior-Version", "uPNSuffixes", "msDS-SPNSuffixes", "fSMORoleOwner"},
	)
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: partitions.Attributes}
	result.FunctionalLevel = admodel.InternalDecodeScalar(
		&decoder,
		"msDS-Behavior-Version",
		admodel.InternalParseUint32,
	)
	result.UPNSuffixes = decoder.InternalTexts("uPNSuffixes")
	result.SPNSuffixes = decoder.InternalTexts("msDS-SPNSuffixes")
	namingMaster := decoder.InternalText("fSMORoleOwner")
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	result.CrossReferences = r.InternalCrossReferences()
	for _, ref := range result.CrossReferences {
		if ref.SystemFlags == nil {
			r.InternalAdd(admodel.ErrIncompleteResult)
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
	if domain := r.InternalRequire(result.RootDomainDN, "rootDomainNamingContext"); domain != "" {
		if ref := r.InternalCrossRefForNC(result.CrossReferences, domain); ref != nil {
			result.Name = ref.DNSRoot
		}
	}
	sites := r.InternalSearch(
		admodel.SearchOptions{
			Base:       "CN=Sites," + configuration,
			Scope:      admodel.ScopeOneLevel,
			Filter:     "(objectClass=site)",
			Properties: []string{"name"},
		},
	)
	for _, raw := range sites.Objects {
		decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
		result.Sites = append(
			result.Sites,
			admodel.ForestSite{Raw: raw, Name: decoder.InternalText("name")},
		)
		r.InternalAdd(errors.Join(decoder.InternalErrors...))
	}
	result.GlobalCatalogs = r.InternalReplicas("", true)
	result.DomainNamingMaster = r.InternalRoleOwner(namingMaster)
	result.SchemaMaster = r.InternalRoleOn(schema, "(objectClass=dMD)")
	return result, nil
}
