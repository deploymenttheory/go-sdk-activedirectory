package model

import (
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

func InternalTrustAttributes(extra []string) ([]string, error) {
	defaults := []string{
		"objectGUID",
		"name",
		"trustPartner",
		"flatName",
		"securityIdentifier",
		"trustDirection",
		"trustType",
		"trustAttributes",
		"msDS-SupportedEncryptionTypes",
	}
	properties := append(defaults, slices.Clone(extra)...)
	normalized, err := InternalSearchOptionsNormalized((SearchOptions{Properties: properties}))
	return normalized.Properties, err
}
