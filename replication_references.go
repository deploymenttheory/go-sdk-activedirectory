package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

type ReplicationReferenceLimits struct{ MaxReferences, MaxRanges, MaxBytes int }
type ReplicationReference struct {
	DistinguishedName string
	Raw               RawValue
}
type ReplicationReferenceRange struct {
	RequestedProperty string
	Attributes        map[string][][]byte
	Error             error
}

// Complete describes contiguous retrieval at one observed GUID/USN, not ACL
// visibility. AttributeReturned distinguishes omission from a returned empty set.
type ReplicationReferencesResult struct {
	References                  []ReplicationReference
	Ranges                      []ReplicationReferenceRange
	AttributeReturned, Complete bool
	Error                       error
}
type replicationRangedReader interface {
	rangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
}

func normalizeReplicationReferenceLimits(limits ReplicationReferenceLimits) (ReplicationReferenceLimits, error) {
	if limits.MaxReferences < 0 || limits.MaxRanges < 0 || limits.MaxBytes < 0 {
		return limits, ErrReplicationReferenceLimit
	}
	if limits.MaxReferences == 0 {
		limits.MaxReferences = 100000
	}
	if limits.MaxRanges == 0 {
		limits.MaxRanges = 1000
	}
	if limits.MaxBytes == 0 {
		limits.MaxBytes = 64 << 20
	}
	return limits, nil
}
func replicationReferenceVersion(object Object) (GUID, uint64, error) {
	guid, e := topologyGUID(object)
	if e != nil {
		return guid, 0, e
	}
	v, e := object.Values("uSNChanged").Single()
	if e != nil {
		return guid, 0, e
	}
	text, e := v.Text()
	if e != nil {
		return guid, 0, e
	}
	usn, e := strconv.ParseUint(text, 10, 64)
	return guid, usn, e
}
func collectReplicationReferences(ctx context.Context, session directorySession, object Object, attribute string, limits ReplicationReferenceLimits) (result ReplicationReferencesResult, err error) {
	defer func() {
		result.Error = err
		if err != nil {
			result.Complete = false
		}
	}()
	reader, ok := session.(replicationRangedReader)
	if !ok {
		return result, ErrUnsupported
	}
	guid, usn, err := replicationReferenceVersion(object)
	if err != nil {
		return result, err
	}
	remaining, start := limits.MaxBytes, uint64(0)
	seen := make(map[string]struct{})
	for {
		if err := context.Cause(ctx); err != nil {
			return result, err
		}
		if len(result.Ranges) >= limits.MaxRanges || len(result.References) >= limits.MaxReferences {
			return result, ErrReplicationReferenceLimit
		}
		count := min(1500, limits.MaxReferences-len(result.References))
		property := fmt.Sprintf("%s;range=%d-%d", attribute, start, start+uint64(count)-1)
		attrs, readErr := reader.rangedBaseObject(ctx, objectGUIDTarget(guid), []string{property, "objectGUID", "uSNChanged"})
		result.Ranges = append(result.Ranges, ReplicationReferenceRange{RequestedProperty: property, Attributes: attrs, Error: readErr})
		for name, values := range attrs {
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(readErr, err)
			}
			remaining -= len(name)
			for _, v := range values {
				if err := context.Cause(ctx); err != nil {
					return result, errors.Join(readErr, err)
				}
				remaining -= len(v)
			}
			if remaining < 0 {
				return result, errors.Join(readErr, ErrReplicationReferenceLimit)
			}
		}
		values, next, terminal, present, rangeErr := directoryReferenceRange(attrs, attribute, start)
		result.AttributeReturned = result.AttributeReturned || present
		if len(values) > limits.MaxReferences-len(result.References) {
			return result, errors.Join(readErr, rangeErr, ErrReplicationReferenceLimit)
		}
		for _, value := range values {
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(readErr, rangeErr, err)
			}
			raw := NewRawValue(value)
			dn, e := raw.Text()
			if e == nil {
				var parsed identityDN
				parsed, e = parseIdentityDN(dn)
				if e == nil {
					key := identityDNKey(parsed)
					if _, exists := seen[key]; exists {
						e = ErrInvalidResult
					}
					seen[key] = struct{}{}
				}
			}
			result.References = append(result.References, ReplicationReference{DistinguishedName: dn, Raw: raw})
			rangeErr = errors.Join(rangeErr, e)
		}
		actualGUID, actualUSN, versionErr := replicationReferenceVersion(Object{Attributes: attrs})
		if versionErr == nil && (actualGUID != guid || actualUSN != usn) {
			versionErr = ErrReplicationReferenceChanged
		}
		if e := errors.Join(readErr, rangeErr, versionErr); e != nil {
			return result, e
		}
		if terminal {
			result.Complete = true
			return result, nil
		}
		start = next
	}
}

// ReplicationReferenceChanges applies either an explicit replacement (a non-nil
// slice, including empty) or disjoint Add/Remove values in one LDAP Modify.
type ReplicationReferenceChanges struct {
	Replace     []Identity
	Add, Remove []Identity
}
type ReplicationReferenceInput struct {
	Identity    Identity
	Observation IdentityResult
}

func replicationReferenceChangesValid(changes ReplicationReferenceChanges) error {
	if changes.Replace != nil && (len(changes.Add) > 0 || len(changes.Remove) > 0) {
		return ErrReplicationTopology
	}
	for _, list := range [][]Identity{changes.Replace, changes.Add, changes.Remove} {
		for _, identity := range list {
			if err := topologyIdentity(identity, ResolveIdentityOptions{}); err != nil {
				return err
			}
		}
	}
	return nil
}
func resolveReplicationReferences(ctx context.Context, session directorySession, config Config, root RootDSE, configuration, parent, class string, identities []Identity, inputs *[]ReplicationReferenceInput) ([][]byte, error) {
	var values [][]byte
	seen := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		if err := context.Cause(ctx); err != nil {
			return values, err
		}
		observed, err := resolveIdentitySession(ctx, session, config, root, identity, ResolveIdentityOptions{Partition: configuration, Properties: []string{"objectGUID", "objectClass"}})
		*inputs = append(*inputs, ReplicationReferenceInput{Identity: identity, Observation: observed})
		if err != nil {
			return values, err
		}
		if err := topologyDirectChild(*observed.Object, parent, class); err != nil {
			return values, err
		}
		dn := observed.Object.DistinguishedName
		parsed, err := parseIdentityDN(dn)
		if err != nil {
			return values, err
		}
		key := identityDNKey(parsed)
		if _, exists := seen[key]; exists {
			return values, ErrReplicationTopology
		}
		seen[key] = struct{}{}
		values = append(values, []byte(dn))
	}
	return values, nil
}
func replicationReferenceMods(ctx context.Context, session directorySession, config Config, root RootDSE, configuration, parent, class, attribute string, changes ReplicationReferenceChanges, inputs *[]ReplicationReferenceInput) ([]ldapAttributeModification, error) {
	if changes.Replace != nil {
		values, err := resolveReplicationReferences(ctx, session, config, root, configuration, parent, class, changes.Replace, inputs)
		if err != nil {
			return nil, err
		}
		if len(values) == 0 {
			return []ldapAttributeModification{{operation: 1, attribute: attribute}}, nil
		}
		return []ldapAttributeModification{{operation: 2, attribute: attribute, values: values}}, nil
	}
	remove, err := resolveReplicationReferences(ctx, session, config, root, configuration, parent, class, changes.Remove, inputs)
	if err != nil {
		return nil, err
	}
	add, err := resolveReplicationReferences(ctx, session, config, root, configuration, parent, class, changes.Add, inputs)
	if err != nil {
		return nil, err
	}
	removed := make(map[string]struct{}, len(remove))
	for _, r := range remove {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		parsed, _ := parseIdentityDN(string(r))
		removed[identityDNKey(parsed)] = struct{}{}
	}
	for _, a := range add {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		parsed, _ := parseIdentityDN(string(a))
		if _, exists := removed[identityDNKey(parsed)]; exists {
			return nil, ErrReplicationTopology
		}
	}
	var mods []ldapAttributeModification
	if len(remove) > 0 {
		mods = append(mods, ldapAttributeModification{operation: 1, attribute: attribute, values: remove})
	}
	if len(add) > 0 {
		mods = append(mods, ldapAttributeModification{operation: 0, attribute: attribute, values: add})
	}
	return mods, nil
}
