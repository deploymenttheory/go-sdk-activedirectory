package model

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Revealed entries are per-secret-attribute markers, not secret values. Several
// markers can name one account. Authenticated entries have SecretAttribute empty.
type RODCPasswordReplicationEntry struct {
	Raw                                RawValue
	DistinguishedName, SecretAttribute string
	Observation                        IdentityResult
	Error                              error
}

// Complete covers contiguous ranges and resolution of the returned references.
// Omission is retained in AttributeReturned; it does not prove ACL visibility.
// Principals are deduplicated by GUID; Entries preserve every raw linked value.
type RODCPasswordReplicationResult struct {
	Controller                                IdentityResult
	Attribute                                 string
	Entries                                   []RODCPasswordReplicationEntry
	Principals                                []MembershipPrincipal
	Ranges                                    []GroupMemberRange
	AttributeReturned, Complete, LimitReached bool
}

func InternalCollectRODCPasswordLinks(
	ctx context.Context,
	session InternalDirectorySession,
	attribute string,
	revealed bool,
	object Object,
	budget *InternalMembershipBudget,
	result *RODCPasswordReplicationResult,
) error {
	reader, ok := session.(InternalGroupMemberReader)
	if !ok {
		return ErrUnsupported
	}
	guid, usn, err := InternalGroupMemberVersion(object)
	if err != nil {
		return err
	}
	start := uint64(0)
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		remaining := budget.InternalLimits.MaxObjects - budget.InternalObjects
		if remaining <= 0 || budget.InternalRanges >= budget.InternalLimits.MaxRanges ||
			budget.InternalBytes >= budget.InternalLimits.MaxBytes {
			return ErrMembershipLimit
		}
		property := fmt.Sprintf(
			"%s;range=%d-%d",
			attribute,
			start,
			start+uint64(min(1500, remaining))-1,
		)
		attrs, readErr := reader.InternalGroupMemberBaseObject(
			ctx,
			InternalObjectGUIDTarget(guid),
			[]string{property, "objectGUID", "uSNChanged"},
			false,
		)
		result.Ranges = append(
			result.Ranges,
			GroupMemberRange{
				RequestedProperty: property,
				Attributes:        attrs,
				ObservedAt:        time.Now().UTC(),
				Error:             readErr,
			},
		)
		budget.InternalRanges++
		if err := budget.InternalAttributes(attrs); err != nil {
			return errors.Join(readErr, err)
		}
		mapped := map[string][][]byte{}
		for name, values := range attrs {
			lower := strings.ToLower(name)
			prefix := strings.ToLower(attribute)
			if lower == prefix || strings.HasPrefix(lower, prefix+";") {
				key := "member" + lower[len(prefix):]
				if _, exists := mapped[key]; exists {
					return errors.Join(readErr, ErrInvalidResult)
				}
				mapped[key] = values
			}
		}
		values, next, terminal, present, rangeErr := InternalGroupMemberRange(mapped, start)
		result.AttributeReturned = result.AttributeReturned || present
		for _, value := range values {
			entry, decodeErr := InternalDecodeRODCPasswordLink(value, revealed)
			entry.Error = decodeErr
			result.Entries = append(result.Entries, entry)
			rangeErr = errors.Join(rangeErr, decodeErr)
			if budget.InternalObjects >= budget.InternalLimits.MaxObjects {
				return errors.Join(readErr, rangeErr, ErrMembershipLimit)
			}
			budget.InternalObjects++
		}
		observedGUID, observedUSN, versionErr := InternalGroupMemberVersion(
			Object{Attributes: attrs},
		)
		if versionErr == nil && (observedGUID != guid || observedUSN != usn) {
			versionErr = ErrGroupMembershipChanged
		}
		if err := errors.Join(readErr, rangeErr, versionErr); err != nil {
			return err
		}
		if terminal {
			return nil
		}
		start = next
	}
}

func InternalDecodeRODCPasswordLink(
	value []byte,
	revealed bool,
) (result RODCPasswordReplicationEntry, err error) {
	result.Raw = NewRawValue(value)
	text, err := result.Raw.Text()
	if err != nil {
		return result, err
	}
	result.DistinguishedName = text
	if revealed {
		parts := strings.SplitN(text, ":", 4)
		if len(parts) != 4 || parts[0] != "S" {
			return result, ErrInvalidResult
		}
		count, parseErr := strconv.ParseUint(parts[1], 10, 32)
		// LDAP display names are ASCII. Their byte and character counts coincide.
		if parseErr != nil || count != uint64(len(parts[2])) ||
			!InternalObjectAttributeName(parts[2]) {
			return result, ErrInvalidResult
		}
		result.SecretAttribute, result.DistinguishedName = parts[2], parts[3]
	}
	_, err = InternalParseIdentityDN(result.DistinguishedName)
	return result, err
}
