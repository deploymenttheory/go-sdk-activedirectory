package activedirectory

import (
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalidMembership              = errors.New("invalid membership options")
	ErrMembershipLimit                = errors.New("membership collection limit reached")
	ErrMembershipContext              = errors.New("membership requires an explicit authenticated context for the target naming context")
	ErrMembershipForeign              = errors.New("foreign security principal could not be resolved uniquely in the supplied contexts")
	ErrMembershipGC                   = errors.New("membership requires an available matching global catalog connection")
	ErrAuthorizationGroupsUnavailable = errors.New("tokenGroups is unavailable or incomplete; authorization membership cannot be established")
)

// MembershipContext explicitly supplies an authenticated connection and NC.
// The SDK does not dial, forward credentials, chase referrals, or close it.
type MembershipContext struct {
	Client    *Client
	Partition string
}

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
type membershipEndpoint struct {
	client    *Client
	root      RootDSE
	partition string
}
type membershipBudget struct {
	limits                         MembershipLimits
	objects, groups, ranges, bytes int
}

func normalizeMembershipLimits(l MembershipLimits) (MembershipLimits, error) {
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
func (b *membershipBudget) attributes(attributes map[string][][]byte) error {
	for name, values := range attributes {
		if len(name) > b.limits.MaxBytes-b.bytes {
			return ErrMembershipLimit
		}
		b.bytes += len(name)
		for _, value := range values {
			if len(value) > b.limits.MaxBytes-b.bytes {
				return ErrMembershipLimit
			}
			b.bytes += len(value)
		}
	}
	return nil
}
func (b *membershipBudget) object(object Object) error {
	if b.objects >= b.limits.MaxObjects {
		return ErrMembershipLimit
	}
	b.objects++
	if len(object.DistinguishedName) > b.limits.MaxBytes-b.bytes {
		return ErrMembershipLimit
	}
	b.bytes += len(object.DistinguishedName)
	return b.attributes(object.Attributes)
}
func membershipProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectClass", "objectGUID", "objectSid", "sAMAccountName", "name", "primaryGroupID", "uSNChanged")
}
func membershipResolveOptions(identity Identity, partition string, extra []string) ResolveIdentityOptions {
	target := IdentityTargetObject
	if identity.Form() == IdentityFormSID || identity.Form() == IdentityFormAccountName {
		target = IdentityTargetAccount
	}
	return ResolveIdentityOptions{Target: target, Partition: partition, Properties: membershipProperties(extra)}
}
func newMembershipEndpoint(ctx context.Context, c *Client, identity Identity, partition string, full bool) (membershipEndpoint, error) {
	e := membershipEndpoint{client: c}
	if c == nil || c.session == nil {
		return e, ErrClosed
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		e.root = root
		if err != nil {
			return err
		}
		if root.Capabilities().Type == DirectoryUnknown {
			return root.Capabilities().RequireADDS("Membership")
		}
		selected := partition
		if selected == "" {
			selected = c.config.Partition
		}
		index, _, err := identityPartition(identity, selected, root)
		if err != nil {
			return err
		}
		e.partition = root.NamingContexts[index]
		if full && root.Capabilities().Type == DirectoryADDS {
			if c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269 {
				return ErrGroupMembershipTarget
			}
			if root.DefaultNamingContext == nil || !membershipSameDN(e.partition, *root.DefaultNamingContext) {
				return ErrMembershipContext
			}
		}
		return nil
	})
	return e, err
}
func membershipSameDN(a, b string) bool {
	left, e1 := parseIdentityDN(a)
	right, e2 := parseIdentityDN(b)
	return e1 == nil && e2 == nil && sameIdentityDN(left, right)
}
func membershipContexts(ctx context.Context, home membershipEndpoint, contexts []MembershipContext) ([]membershipEndpoint, error) {
	if len(contexts) > 64 {
		return nil, ErrMembershipLimit
	}
	result := []membershipEndpoint{home}
	for _, item := range contexts {
		identity, err := IdentityByDN(item.Partition)
		if err != nil {
			return result, errors.Join(ErrMembershipContext, err)
		}
		for _, old := range result {
			if membershipSameDN(old.partition, item.Partition) {
				return result, ErrMembershipContext
			}
		}
		endpoint, err := newMembershipEndpoint(ctx, item.Client, identity, item.Partition, true)
		if err != nil {
			return result, err
		}
		result = append(result, endpoint)
	}
	return result, nil
}
func membershipDNEndpoint(dn string, endpoints []membershipEndpoint) (int, error) {
	identity, err := IdentityByDN(dn)
	if err != nil {
		return -1, err
	}
	best, depth := -1, -1
	for i, e := range endpoints {
		parsed, _ := parseIdentityDN(e.partition)
		_, _, err := identityPartition(identity, e.partition, e.root)
		if err == nil && len(parsed) > depth {
			best, depth = i, len(parsed)
		}
	}
	if best < 0 {
		return -1, ErrMembershipContext
	}
	return best, nil
}
func (e membershipEndpoint) resolve(ctx context.Context, identity Identity, extra []string) (IdentityResult, error) {
	var result IdentityResult
	err := e.client.read(ctx, func(ctx context.Context) error {
		var err error
		result, err = resolveIdentitySession(ctx, e.client.session, e.client.config, e.root, identity, membershipResolveOptions(identity, e.partition, extra))
		return err
	})
	return result, err
}
func (e membershipEndpoint) search(ctx context.Context, query SearchOptions) (SearchResult, error) {
	var result SearchResult
	err := e.client.read(ctx, func(ctx context.Context) error {
		var err error
		result, err = searchIdentitySession(ctx, e.client.session, query)
		return err
	})
	return result, err
}
func membershipHasClass(object Object, name string) bool {
	values, _ := object.Attribute("objectClass")
	for _, v := range values {
		if strings.EqualFold(string(v), name) {
			return true
		}
	}
	return false
}
func decodeMembershipPrincipal(object Object, source Endpoint) (MembershipPrincipal, error) {
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
func membershipDomainRID(sid SID) (uint32, bool) {
	data := sid.Bytes()
	if len(data) != 28 || data[1] != 5 || data[2] != 0 || data[3] != 0 || data[4] != 0 || data[5] != 0 || data[6] != 0 || data[7] != 5 || binary.LittleEndian.Uint32(data[8:12]) != 21 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(data[24:]), true
}
func membershipPrimarySID(object Object) (SID, bool, error) {
	values := object.Values("primaryGroupID")
	if values.State != AttributePresent {
		if membershipHasClass(object, "user") {
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
	if _, ok := membershipDomainRID(sid); !ok {
		return SID{}, false, ErrInvalidValue
	}
	data := sid.Bytes()
	binary.LittleEndian.PutUint32(data[24:], uint32(rid))
	sid, err = SIDFromBytes(data)
	return sid, err == nil, err
}
