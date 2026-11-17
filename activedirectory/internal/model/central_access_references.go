package model

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// CentralAccessReferenceLimits are per-source budgets. Zero selects a default;
// positive values override that default (they are not capped at the default).
type (
	CentralAccessReferenceLimits struct{ MaxReferences, MaxRanges, MaxBytes int }
	CentralAccessReference       struct {
		DistinguishedName string
		Raw               RawValue
	}
)

type CentralAccessReferenceRange struct {
	RequestedProperty string
	Attributes        map[string][][]byte
	Error             error
}

// Complete means contiguous retrieval at one observed source GUID/USN. It does
// not prove ACL visibility or a snapshot across the referenced objects.
type CentralAccessReferencesResult struct {
	References                  []CentralAccessReference
	Ranges                      []CentralAccessReferenceRange
	AttributeReturned, Complete bool
	Error                       error
}
type InternalCentralAccessRangedSession interface {
	InternalRangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
}

func InternalNormalizeCentralAccessLimits(
	limits CentralAccessReferenceLimits,
) (CentralAccessReferenceLimits, error) {
	if limits.MaxReferences < 0 || limits.MaxRanges < 0 || limits.MaxBytes < 0 {
		return limits, ErrCentralAccessReferences
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

func InternalCentralAccessVersion(object Object) (GUID, uint64, error) {
	guid, err := InternalCentralAccessGUID(object)
	if err != nil {
		return guid, 0, err
	}
	value, err := object.Values("uSNChanged").Single()
	if err != nil {
		return guid, 0, err
	}
	text, err := value.Text()
	if err != nil {
		return guid, 0, err
	}
	usn, err := strconv.ParseUint(text, 10, 64)
	return guid, usn, err
}

func InternalReadCentralAccessReferences(
	ctx context.Context,
	session InternalDirectorySession,
	object Object,
	attribute string,
	limits CentralAccessReferenceLimits,
) (result CentralAccessReferencesResult, err error) {
	defer func() {
		result.Error = err
		if err != nil {
			result.Complete = false
		}
	}()
	reader, ok := session.(InternalCentralAccessRangedSession)
	if !ok {
		return result, ErrUnsupported
	}
	guid, usn, err := InternalCentralAccessVersion(object)
	if err != nil {
		return result, err
	}
	seen := map[string]struct{}{}
	start, remaining := uint64(0), limits.MaxBytes
	for {
		if err := context.Cause(ctx); err != nil {
			return result, err
		}
		if len(result.Ranges) >= limits.MaxRanges ||
			len(result.References) >= limits.MaxReferences {
			return result, ErrCentralAccessReferences
		}
		count := min(1500, limits.MaxReferences-len(result.References))
		property := fmt.Sprintf("%s;range=%d-%d", attribute, start, start+uint64(count)-1)
		attrs, readErr := reader.InternalRangedBaseObject(
			ctx,
			InternalObjectGUIDTarget(guid),
			[]string{property, "objectGUID", "uSNChanged"},
		)
		result.Ranges = append(
			result.Ranges,
			CentralAccessReferenceRange{
				RequestedProperty: property,
				Attributes:        attrs,
				Error:             readErr,
			},
		)
		for name, values := range attrs {
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(readErr, err)
			}
			if len(name) > remaining {
				return result, errors.Join(readErr, ErrCentralAccessReferences)
			}
			remaining -= len(name)
			for _, value := range values {
				if err := context.Cause(ctx); err != nil {
					return result, errors.Join(readErr, err)
				}
				if len(value) > remaining {
					return result, errors.Join(readErr, ErrCentralAccessReferences)
				}
				remaining -= len(value)
			}
		}
		values, next, terminal, present, rangeErr := InternalDirectoryReferenceRange(
			attrs,
			attribute,
			start,
		)
		result.AttributeReturned = result.AttributeReturned || present
		if len(values) > limits.MaxReferences-len(result.References) {
			return result, errors.Join(readErr, rangeErr, ErrCentralAccessReferences)
		}
		for _, value := range values {
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(readErr, rangeErr, err)
			}
			raw := NewRawValue(value)
			dn, e := raw.Text()
			if e == nil {
				var parsed InternalIdentityDN
				parsed, e = InternalParseIdentityDN(dn)
				if e == nil {
					key := InternalIdentityDNKey(parsed)
					if _, exists := seen[key]; exists {
						e = ErrInvalidResult
					}
					seen[key] = struct{}{}
				}
			}
			result.References = append(
				result.References,
				CentralAccessReference{DistinguishedName: dn, Raw: raw},
			)
			rangeErr = errors.Join(rangeErr, e)
		}
		actualGUID, actualUSN, versionErr := InternalCentralAccessVersion(Object{Attributes: attrs})
		if versionErr == nil && (actualGUID != guid || actualUSN != usn) {
			versionErr = ErrCentralAccessReferences
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

type CentralAccessPolicyMembersRequest struct {
	Identity Identity
	Members  []Identity
	Options  ObjectMutationOptions
}
type CentralAccessMemberInput struct {
	Identity    Identity
	Observation IdentityResult
}
type CentralAccessPolicyMembersResult struct {
	Mutation      ObjectMutationResult
	Inputs        []CentralAccessMemberInput
	Before, After CentralAccessReferencesResult
}
