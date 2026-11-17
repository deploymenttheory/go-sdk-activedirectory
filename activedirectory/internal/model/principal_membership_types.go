package model

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalidMembership = errors.New("invalid membership options")
	ErrMembershipLimit   = errors.New("membership collection limit reached")
	ErrMembershipContext = errors.New(
		"membership requires an explicit authenticated context for the target naming context",
	)
	ErrMembershipForeign = errors.New(
		"foreign security principal could not be resolved uniquely in the supplied contexts",
	)
	ErrMembershipGC = errors.New(
		"membership requires an available matching global catalog connection",
	)
	ErrAuthorizationGroupsUnavailable = errors.New(
		"tokenGroups is unavailable or incomplete; authorization membership cannot be established",
	)
)

// Zero limits select 100000 objects, 1000 groups/ranges, depth 32 and 64 MiB.
// A received native batch is retained on overflow, then no next read is made.
type MembershipLimits struct{ MaxObjects, MaxGroups, MaxRanges, MaxDepth, MaxBytes int }

type MembershipPrincipal struct {
	Source Endpoint
	Object Object
	GUID   GUID
	SID    SID
	// Primary records a primary-group edge encountered anywhere in the traversal.
	Primary bool
}
type MembershipResolution struct {
	Reference        string
	Source           Endpoint
	Observation      IdentityResult
	ForeignReference *Object
	Error            error
	Lookups          []MembershipLookup
}
type MembershipLookup struct {
	Observation IdentityResult
	Error       error
}
type MembershipSearch struct {
	Source      Endpoint
	Query       SearchOptions
	Observation SearchResult
	Error       error
}

type InternalMembershipBudget struct {
	InternalLimits                                                 MembershipLimits
	InternalObjects, InternalGroups, InternalRanges, InternalBytes int
}

func InternalNormalizeMembershipLimits(l MembershipLimits) (MembershipLimits, error) {
	if l.MaxObjects < 0 || l.MaxGroups < 0 || l.MaxRanges < 0 || l.MaxDepth < 0 || l.MaxBytes < 0 {
		return l, ErrInvalidMembership
	}
	if l.MaxObjects == 0 {
		l.MaxObjects = 100000
	}
	if l.MaxGroups == 0 {
		l.MaxGroups = 1000
	}
	if l.MaxRanges == 0 {
		l.MaxRanges = 1000
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = 32
	}
	if l.MaxBytes == 0 {
		l.MaxBytes = 64 << 20
	}
	return l, nil
}

func (b *InternalMembershipBudget) InternalAttributes(attributes map[string][][]byte) error {
	for name, values := range attributes {
		if len(name) > b.InternalLimits.MaxBytes-b.InternalBytes {
			return ErrMembershipLimit
		}
		b.InternalBytes += len(name)
		for _, value := range values {
			if len(value) > b.InternalLimits.MaxBytes-b.InternalBytes {
				return ErrMembershipLimit
			}
			b.InternalBytes += len(value)
		}
	}
	return nil
}

func (b *InternalMembershipBudget) InternalObject(object Object) error {
	if b.InternalObjects >= b.InternalLimits.MaxObjects {
		return ErrMembershipLimit
	}
	b.InternalObjects++
	if len(object.DistinguishedName) > b.InternalLimits.MaxBytes-b.InternalBytes {
		return ErrMembershipLimit
	}
	b.InternalBytes += len(object.DistinguishedName)
	return b.InternalAttributes(object.Attributes)
}

func InternalMembershipProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectClass",
		"objectGUID",
		"objectSid",
		"sAMAccountName",
		"name",
		"primaryGroupID",
		"uSNChanged",
	)
}

func InternalMembershipResolveOptions(
	identity Identity,
	partition string,
	extra []string,
) ResolveIdentityOptions {
	target := IdentityTargetObject
	if identity.Form() == IdentityFormSID || identity.Form() == IdentityFormAccountName {
		target = IdentityTargetAccount
	}
	return ResolveIdentityOptions{
		Target:     target,
		Partition:  partition,
		Properties: InternalMembershipProperties(extra),
	}
}

func InternalMembershipSameDN(a, b string) bool {
	left, e1 := InternalParseIdentityDN(a)
	right, e2 := InternalParseIdentityDN(b)
	return e1 == nil && e2 == nil && InternalSameIdentityDN(left, right)
}

func InternalMembershipHasClass(object Object, name string) bool {
	values, _ := object.Attribute("objectClass")
	for _, v := range values {
		if strings.EqualFold(string(v), name) {
			return true
		}
	}
	return false
}

func InternalDecodeMembershipPrincipal(
	object Object,
	source Endpoint,
) (MembershipPrincipal, error) {
	p := MembershipPrincipal{Source: source, Object: object}
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return p, err
	}
	p.GUID, err = value.GUID()
	if err != nil {
		return p, err
	}
	value, err = object.Values("objectSid").Single()
	if err != nil {
		return p, err
	}
	p.SID, err = value.SID()
	return p, err
}

func InternalMembershipDomainRID(sid SID) (uint32, bool) {
	data := sid.Bytes()
	if len(data) != 28 || data[1] != 5 || data[2] != 0 || data[3] != 0 || data[4] != 0 ||
		data[5] != 0 ||
		data[6] != 0 ||
		data[7] != 5 ||
		binary.LittleEndian.Uint32(data[8:12]) != 21 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data[24:]), true
}

func InternalMembershipPrimarySID(object Object) (SID, bool, error) {
	values := object.Values("primaryGroupID")
	if values.State != AttributePresent {
		if InternalMembershipHasClass(object, "user") {
			return SID{}, false, ErrAttributeUnavailable
		}
		return SID{}, false, nil
	}
	value, err := values.Single()
	if err != nil {
		return SID{}, false, err
	}
	rid, err := value.Int64()
	if err != nil || rid < 0 || rid > 1<<32-1 {
		return SID{}, false, ErrInvalidValue
	}
	value, err = object.Values("objectSid").Single()
	if err != nil {
		return SID{}, false, err
	}
	sid, err := value.SID()
	if err != nil {
		return SID{}, false, err
	}
	if _, ok := InternalMembershipDomainRID(sid); !ok {
		return SID{}, false, ErrInvalidValue
	}
	data := sid.Bytes()
	binary.LittleEndian.PutUint32(data[24:], uint32(rid))
	sid, err = SIDFromBytes(data)
	return sid, err == nil, err
}
