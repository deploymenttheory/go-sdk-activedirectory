package model

import (
	"context"
	"errors"
	"strings"
)

// Prerequisites are observations on the selected DC, not an authorization or
// password-retrieval guarantee. KDS contains metadata only, never root key data.
type ServiceAccountPrerequisites struct {
	RootDSE         RootDSE
	Domain          IdentityResult
	Schema          SearchResult
	KDS             SearchResult
	EligibleKDSKeys []string
	Complete        bool
}

func InternalServiceAccountPrerequisites(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
	kind ServiceAccountKind,
	partition string,
) (result ServiceAccountPrerequisites, err error) {
	result.RootDSE = root
	fail := func(e error) (ServiceAccountPrerequisites, error) {
		return result, errors.Join(ErrServiceAccountPrerequisite, e)
	}
	if e := root.Capabilities().RequireADDS("CreateServiceAccount"); e != nil {
		return fail(e)
	}
	if config.Endpoint.Port == 3268 || config.Endpoint.Port == 3269 ||
		root.Capabilities().Has("1.2.840.113556.1.4.1920") {
		return fail(ErrObjectWriteTarget)
	}
	minimum := uint32(4)
	if kind == ServiceAccountGroupManaged {
		minimum = 5
	}
	if root.DomainControllerFunctionality == nil || *root.DomainControllerFunctionality < minimum ||
		root.SchemaNamingContext == nil ||
		root.DefaultNamingContext == nil {
		return fail(ErrAttributeUnavailable)
	}
	if partition == "" {
		partition = config.Partition
	}
	if partition == "" {
		partition = *root.DefaultNamingContext
	}
	identity, e := IdentityByDN(partition)
	if e != nil {
		return fail(e)
	}
	result.Domain, e = InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		identity,
		ResolveIdentityOptions{
			Partition:  partition,
			Properties: []string{"objectClass", "instanceType", "objectGUID"},
		},
	)
	if e != nil {
		return fail(e)
	}
	d := InternalRootDSEDecoder{InternalAttributes: result.Domain.Object.Attributes}
	classes := d.InternalTexts("objectClass")
	instance := InternalDecodeScalar(&d, "instanceType", InternalParseUint32)
	domain := false
	for _, class := range classes {
		domain = domain || strings.EqualFold(class, "domainDNS")
	}
	if !domain || instance == nil || *instance&4 == 0 {
		return fail(errors.Join(ErrObjectWriteTarget, errors.Join(d.InternalErrors...)))
	}
	result.Schema, e = InternalSearchIdentitySession(
		ctx,
		session,
		SearchOptions{
			Base:  *root.SchemaNamingContext,
			Scope: ScopeOneLevel,
			TypedFilter: FilterAnd(
				FilterEqual("objectClass", FilterText("classSchema")),
				FilterEqual("ldapDisplayName", FilterText(InternalServiceAccountClassName(kind))),
			),
			Properties:  []string{"ldapDisplayName", "isDefunct", "objectClassCategory"},
			ResultLimit: 2,
		},
	)
	if e != nil {
		return fail(e)
	}
	if !result.Schema.Complete || len(result.Schema.Objects) != 1 {
		return fail(ErrInvalidResult)
	}
	d = InternalRootDSEDecoder{InternalAttributes: result.Schema.Objects[0].Attributes}
	defunct := InternalDecodeScalar(&d, "isDefunct", InternalParseLDAPBool)
	category := InternalDecodeScalar(&d, "objectClassCategory", InternalParseUint32)
	if (defunct != nil && *defunct) || category == nil || *category != 1 ||
		len(d.InternalErrors) > 0 {
		return fail(errors.Join(ErrInvalidResult, errors.Join(d.InternalErrors...)))
	}
	if kind == ServiceAccountGroupManaged {
		if root.ConfigurationNamingContext == nil || root.CurrentTime == nil {
			return fail(ErrAttributeUnavailable)
		}
		result.KDS, e = InternalSearchIdentitySession(
			ctx,
			session,
			SearchOptions{
				Base:        "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services," + *root.ConfigurationNamingContext,
				Scope:       ScopeOneLevel,
				TypedFilter: FilterEqual("objectClass", FilterText("msKds-ProvRootKey")),
				Properties:  []string{"cn", "msKds-UseStartTime", "msKds-CreateTime"},
				ResultLimit: 128,
			},
		)
		if e != nil {
			return fail(e)
		}
		if !result.KDS.Complete {
			return fail(ErrIncompleteResult)
		}
		now, e := FileTimeFromTime(*root.CurrentTime)
		if e != nil {
			return fail(e)
		}
		// GKDI uses 10-hour intervals. A future key within the current interval
		// cannot authorize its start; compare against the current interval start.
		const cycle = uint64(360000000000)
		start := uint64(now) / cycle * cycle
		for _, key := range result.KDS.Objects {
			value, e := key.Values("msKds-UseStartTime").Single()
			if e != nil {
				return fail(e)
			}
			ticks, e := value.Int64()
			if e != nil || ticks < 0 {
				return fail(errors.Join(ErrInvalidResult, e))
			}
			if uint64(ticks) <= start {
				result.EligibleKDSKeys = append(result.EligibleKDSKeys, key.DistinguishedName)
			}
		}
		if len(result.EligibleKDSKeys) == 0 {
			return fail(ErrAttributeUnavailable)
		}
	}
	result.Complete = true
	return result, nil
}

func InternalServiceAccountDefaultParent(
	ctx context.Context,
	session InternalDirectorySession,
	config Config,
	root RootDSE,
	parent Identity,
	options ObjectMutationOptions,
) (Identity, error) {
	if parent.Form() != 0 {
		return parent, nil
	}
	partition := options.Partition
	if partition == "" {
		partition = config.Partition
	}
	if partition == "" && root.DefaultNamingContext != nil {
		partition = *root.DefaultNamingContext
	}
	identity, err := IdentityByDN(partition)
	if err != nil {
		return Identity{}, err
	}
	observed, err := InternalResolveIdentitySession(
		ctx,
		session,
		config,
		root,
		identity,
		ResolveIdentityOptions{
			Partition:  partition,
			Properties: []string{"objectGUID", "otherWellKnownObjects"},
		},
	)
	fail := func(e error) (Identity, error) {
		return Identity{}, &AccountCreationParentError{Observation: observed, Cause: e}
	}
	if err != nil {
		return fail(err)
	}
	if observed.Object.Values("otherWellKnownObjects").State != AttributePresent {
		return fail(ErrAttributeUnavailable)
	}
	// Reuse the bounded DN-binary decoder with the other-well-known projection.
	d := InternalRootDSEDecoder{
		InternalAttributes: map[string][][]byte{
			"wellknownobjects": observed.Object.Attributes["otherwellknownobjects"],
		},
	}
	containers := InternalWellKnownContainers(&d)
	if err = errors.Join(d.InternalErrors...); err != nil {
		return fail(err)
	}
	parent, err = IdentityByDN(containers["1EB93889E40C45DF9F0C64D23BBB6237"])
	if err != nil {
		return fail(err)
	}
	if _, _, err = InternalIdentityPartition(parent, partition, root); err != nil {
		return fail(err)
	}
	return parent, nil
}
