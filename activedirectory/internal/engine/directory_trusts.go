package engine

import (
	"context"
	"errors"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Trust reads one explicit trustedDomain DN from the authenticated endpoint.
// No AD DS-only guard is imposed: LDAP schema/query outcomes remain explicit on
// LDS. This does not establish Get-ADTrust's still-unverified LDS applicability.
//
// Related cmdlet: Get-ADTrust.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2025-ps
func (d *DirectoryService) Trust(
	ctx context.Context,
	distinguishedName string,
	options admodel.TrustOptions,
) (result admodel.TrustResult, err error) {
	if distinguishedName == "" || !admodel.InternalValidDirectoryText(distinguishedName) {
		return result, admodel.ErrInvalidDirectoryQuery
	}
	properties, err := admodel.InternalTrustAttributes(options.Properties)
	if err != nil {
		return result, err
	}
	r, err := InternalDirectoryServiceBegin(d, ctx, "Trust", false)
	if err != nil {
		return result, err
	}
	defer func() { err = r.InternalFinish(&result.Observation) }()
	if !r.InternalReady {
		return result, nil
	}
	result.Trust = r.InternalTrust(
		r.InternalOne(distinguishedName, "(objectClass=trustedDomain)", properties),
	)
	return result, nil
}

// Trusts searches trustedDomain objects in one selected System container or explicit base DN. Query
// selects the domain or base, LDAP filter, properties, paging, and result bounds; this does not
// traverse every domain in the forest.
//
// Related cmdlet: Get-ADTrust.
// Microsoft docs: https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2025-ps
func (d *DirectoryService) Trusts(
	ctx context.Context,
	query admodel.TrustQuery,
) (result admodel.TrustsResult, err error) {
	if query.BaseDN != "" && query.DomainDN != "" ||
		!admodel.InternalValidDirectoryText(query.BaseDN) ||
		!admodel.InternalValidDirectoryText(query.DomainDN) ||
		!admodel.InternalValidDirectoryText(query.LDAPFilter) {
		return result, admodel.ErrInvalidDirectoryQuery
	}
	properties, err := admodel.InternalTrustAttributes(query.Properties)
	if err != nil {
		return result, err
	}
	filter := "(objectClass=trustedDomain)"
	if query.LDAPFilter != "" {
		filter = "(&" + filter + query.LDAPFilter + ")"
	}
	options := admodel.SearchOptions{
		Scope:       admodel.ScopeOneLevel,
		Filter:      filter,
		Properties:  properties,
		PageSize:    query.PageSize,
		ResultLimit: query.ResultLimit,
	}
	if err := options.Validate(); err != nil {
		return result, err
	}
	r, err := InternalDirectoryServiceBegin(d, ctx, "Trusts", false)
	if err != nil {
		return result, err
	}
	defer func() { err = r.InternalFinish(&result.Observation) }()
	if !r.InternalReady {
		return result, nil
	}
	options.Base = query.BaseDN
	if options.Base == "" {
		domain := r.InternalSelectedDomain(query.DomainDN)
		if domain == "" {
			return result, nil
		}
		raw := r.InternalOne(domain, "(objectClass=*)", []string{"wellKnownObjects"})
		decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
		containers := admodel.InternalWellKnownContainers(&decoder)
		r.InternalAdd(errors.Join(decoder.InternalErrors...))
		options.Base = r.InternalContainer(containers, admodel.InternalWellKnownSystem)
		if options.Base == "" {
			return result, nil
		}
	}
	search := r.InternalSearch(options)
	result.LimitReached = search.LimitReached
	for _, raw := range search.Objects {
		result.Trusts = append(result.Trusts, r.InternalTrust(raw))
	}
	return result, nil
}

func (r *InternalDirectoryRead) InternalTrust(raw admodel.Object) admodel.Trust {
	decoder := admodel.InternalRootDSEDecoder{InternalAttributes: raw.Attributes}
	result := admodel.Trust{
		Raw:                raw,
		ObjectGUID:         admodel.InternalCopiedBinary(&decoder, "objectGUID", 16),
		SecurityIdentifier: admodel.InternalCopiedBinary(&decoder, "securityIdentifier", 0),
		Name:               decoder.InternalText("name"),
		Partner:            decoder.InternalText("trustPartner"),
		FlatName:           decoder.InternalText("flatName"),
	}
	result.Direction = admodel.InternalDecodeScalar(
		&decoder,
		"trustDirection",
		admodel.InternalParseUint32,
	)
	result.Type = admodel.InternalDecodeScalar(&decoder, "trustType", admodel.InternalParseUint32)
	result.AttributesMask = admodel.InternalDecodeScalar(
		&decoder,
		"trustAttributes",
		admodel.InternalParseDirectoryMask,
	)
	result.SupportedEncryptionTypes = admodel.InternalDecodeScalar(
		&decoder,
		"msDS-SupportedEncryptionTypes",
		admodel.InternalParseDirectoryMask,
	)
	r.InternalAdd(errors.Join(decoder.InternalErrors...))
	return result
}
