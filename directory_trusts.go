package activedirectory

import (
	"context"
	"errors"
	"slices"
)

// Trust is a trustedDomain object observed from its source partition. Direction
// and type retain unknown numeric values; AttributesMask retains unknown bits.
// SecurityIdentifier identifies the partner domain and is not objectSid.
type Trust struct {
	Raw                      Object
	ObjectGUID               []byte
	Name                     *string
	Partner                  *string
	FlatName                 *string
	SecurityIdentifier       []byte
	Direction                *uint32
	Type                     *uint32
	AttributesMask           *uint32
	SupportedEncryptionTypes *uint32
}

// TrustOptions adds raw attributes to the stable projection. "*" is explicit;
// default properties never include trust authentication secrets. As elsewhere,
// caller-requested raw properties may be sensitive and must not be logged.
type TrustOptions struct{ Properties []string }

type TrustResult struct {
	Observation DirectoryObservation
	Trust       Trust
}
type TrustsResult struct {
	Observation  DirectoryObservation
	Trusts       []Trust
	LimitReached bool
}

// TrustQuery is explicitly a domain/partition query, not a forest-wide traversal.
// BaseDN selects a container directly (including an LDS application partition).
// Otherwise DomainDN or the configured/default NC supplies wellKnownObjects to
// locate System. BaseDN and DomainDN are mutually exclusive. LDAPFilter uses
// LDAP syntax; PowerShell expressions and InputObject require shared resolvers.
type TrustQuery struct {
	BaseDN      string
	DomainDN    string
	LDAPFilter  string
	Properties  []string
	PageSize    int
	ResultLimit int
}

func trustAttributes(extra []string) ([]string, error) {
	defaults := []string{"objectGUID", "name", "trustPartner", "flatName", "securityIdentifier", "trustDirection", "trustType", "trustAttributes", "msDS-SupportedEncryptionTypes"}
	properties := append(defaults, slices.Clone(extra)...)
	normalized, err := (SearchOptions{Properties: properties}).normalized()
	return normalized.Properties, err
}

// Trust reads one explicit trustedDomain DN from the authenticated endpoint.
// No AD DS-only guard is imposed: LDAP schema/query outcomes remain explicit on
// LDS. This does not establish Get-ADTrust's still-unverified LDS applicability.
func (d *DirectoryService) Trust(ctx context.Context, distinguishedName string, options TrustOptions) (result TrustResult, err error) {
	if distinguishedName == "" || !validDirectoryText(distinguishedName) {
		return result, ErrInvalidDirectoryQuery
	}
	properties, err := trustAttributes(options.Properties)
	if err != nil {
		return result, err
	}
	r, err := d.begin(ctx, "Trust", false)
	if err != nil {
		return result, err
	}
	defer func() { err = r.finish(&result.Observation) }()
	if !r.ready {
		return result, nil
	}
	result.Trust = r.trust(r.one(distinguishedName, "(objectClass=trustedDomain)", properties))
	return result, nil
}

func (d *DirectoryService) Trusts(ctx context.Context, query TrustQuery) (result TrustsResult, err error) {
	if query.BaseDN != "" && query.DomainDN != "" || !validDirectoryText(query.BaseDN) || !validDirectoryText(query.DomainDN) || !validDirectoryText(query.LDAPFilter) {
		return result, ErrInvalidDirectoryQuery
	}
	properties, err := trustAttributes(query.Properties)
	if err != nil {
		return result, err
	}
	filter := "(objectClass=trustedDomain)"
	if query.LDAPFilter != "" {
		filter = "(&" + filter + query.LDAPFilter + ")"
	}
	options := SearchOptions{Scope: ScopeOneLevel, Filter: filter, Properties: properties, PageSize: query.PageSize, ResultLimit: query.ResultLimit}
	if err := options.Validate(); err != nil {
		return result, err
	}
	r, err := d.begin(ctx, "Trusts", false)
	if err != nil {
		return result, err
	}
	defer func() { err = r.finish(&result.Observation) }()
	if !r.ready {
		return result, nil
	}
	options.Base = query.BaseDN
	if options.Base == "" {
		domain := r.selectedDomain(query.DomainDN)
		if domain == "" {
			return result, nil
		}
		raw := r.one(domain, "(objectClass=*)", []string{"wellKnownObjects"})
		decoder := rootDSEDecoder{attributes: raw.Attributes}
		containers := wellKnownContainers(&decoder)
		r.add(errors.Join(decoder.errors...))
		options.Base = r.container(containers, wellKnownSystem)
		if options.Base == "" {
			return result, nil
		}
	}
	search := r.search(options)
	result.LimitReached = search.LimitReached
	for _, raw := range search.Objects {
		result.Trusts = append(result.Trusts, r.trust(raw))
	}
	return result, nil
}

func (r *directoryRead) trust(raw Object) Trust {
	decoder := rootDSEDecoder{attributes: raw.Attributes}
	result := Trust{Raw: raw, ObjectGUID: copiedBinary(&decoder, "objectGUID", 16), SecurityIdentifier: copiedBinary(&decoder, "securityIdentifier", 0), Name: decoder.text("name"), Partner: decoder.text("trustPartner"), FlatName: decoder.text("flatName")}
	result.Direction = decodeScalar(&decoder, "trustDirection", parseUint32)
	result.Type = decodeScalar(&decoder, "trustType", parseUint32)
	result.AttributesMask = decodeScalar(&decoder, "trustAttributes", parseDirectoryMask)
	result.SupportedEncryptionTypes = decodeScalar(&decoder, "msDS-SupportedEncryptionTypes", parseDirectoryMask)
	r.add(errors.Join(decoder.errors...))
	return result
}
