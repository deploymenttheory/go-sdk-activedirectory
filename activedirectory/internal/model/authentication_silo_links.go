package model

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

const (
	InternalAuthenticationSiloMaxRanges         = 1000
	InternalAuthenticationSiloMaxAttributeBytes = 64 << 20
)

func InternalSiloObjectVersion(object Object) (GUID, uint64, error) {
	var guid GUID
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return guid, 0, err
	}
	guid, err = value.GUID()
	if err != nil {
		return guid, 0, err
	}
	value, err = object.Values("uSNChanged").Single()
	if err != nil {
		return guid, 0, err
	}
	version, err := strconv.ParseUint(string(value.Bytes()), 10, 64)
	return guid, version, err
}

func InternalReadAuthenticationSiloLinks(
	ctx context.Context,
	session InternalDirectorySession,
	initial Object,
	attribute string,
	limit int,
) (AuthenticationSiloLinks, error) {
	var result AuthenticationSiloLinks
	reader, ok := session.(interface {
		InternalRangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
	})
	if !ok {
		return result, ErrUnsupported
	}
	guid, version, err := InternalSiloObjectVersion(initial)
	if err != nil {
		return result, errors.Join(ErrInvalidResult, err)
	}
	seen := map[string]bool{}
	var start uint64
	remainingBytes := InternalAuthenticationSiloMaxAttributeBytes
	for {
		if err := context.Cause(ctx); err != nil {
			return result, err
		}
		if len(result.Observations) == InternalAuthenticationSiloMaxRanges {
			result.LimitReached = true
			return result, ErrIncompleteResult
		}
		properties := []string{
			"objectGUID",
			"uSNChanged",
			fmt.Sprintf("%s;range=%d-*", attribute, start),
		}
		attrs, readErr := reader.InternalRangedBaseObject(
			ctx,
			InternalObjectGUIDTarget(guid),
			properties,
		)
		object := Object{
			DistinguishedName:   initial.DistinguishedName,
			Attributes:          attrs,
			RequestedProperties: properties,
		}
		result.Observations = append(result.Observations, object)
		exceeded, chargeErr := InternalChargeAuthenticationSiloAttributes(
			ctx,
			attrs,
			&remainingBytes,
		)
		if exceeded || chargeErr != nil {
			result.LimitReached = exceeded
			return result, errors.Join(ErrIncompleteResult, readErr, chargeErr)
		}
		values, next, terminal, present, rangeErr := InternalDirectoryReferenceRange(
			attrs,
			attribute,
			start,
		)
		result.AttributeReturned = result.AttributeReturned || present
		for _, raw := range values {
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(ErrIncompleteResult, readErr, rangeErr, err)
			}
			if len(result.DistinguishedNames) == limit {
				result.LimitReached = true
				break
			}
			dn, err := InternalParseIdentityDN(string(raw))
			if err != nil {
				rangeErr = errors.Join(rangeErr, ErrInvalidResult, err)
				break
			}
			key := InternalIdentityDNKey(dn)
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(ErrIncompleteResult, readErr, rangeErr, err)
			}
			if seen[key] {
				rangeErr = errors.Join(rangeErr, ErrAuthenticationSiloChanged)
				break
			}
			seen[key] = true
			result.DistinguishedNames = append(result.DistinguishedNames, string(raw))
		}
		currentGUID, currentVersion, versionErr := InternalSiloObjectVersion(object)
		if versionErr != nil || guid != currentGUID || version != currentVersion {
			rangeErr = errors.Join(rangeErr, ErrAuthenticationSiloChanged, versionErr)
		}
		if readErr != nil || rangeErr != nil {
			return result, errors.Join(ErrIncompleteResult, readErr, rangeErr)
		}
		if result.LimitReached || (!terminal && len(result.DistinguishedNames) == limit) {
			result.LimitReached = true
			return result, ErrIncompleteResult
		}
		if terminal {
			if err := context.Cause(ctx); err != nil {
				return result, errors.Join(ErrIncompleteResult, err)
			}
			result.Complete = true
			return result, nil
		}
		start = next
	}
}

// Charge all returned attribute names and values before parsing linked DNs.
// Raw observations are retained even when the response crosses the budget.
func InternalChargeAuthenticationSiloAttributes(
	ctx context.Context,
	attrs map[string][][]byte,
	remaining *int,
) (bool, error) {
	for name, values := range attrs {
		if err := context.Cause(ctx); err != nil {
			return false, err
		}
		if len(name) > *remaining {
			return true, nil
		}
		*remaining -= len(name)
		for _, value := range values {
			if err := context.Cause(ctx); err != nil {
				return false, err
			}
			if len(value) > *remaining {
				return true, nil
			}
			*remaining -= len(value)
		}
	}
	return false, context.Cause(ctx)
}

func InternalAuthenticationSiloContains(
	ctx context.Context,
	links AuthenticationSiloLinks,
	dn string,
) (bool, error) {
	if err := context.Cause(ctx); err != nil {
		return false, err
	}
	target, err := InternalParseIdentityDN(dn)
	if err != nil {
		return false, err
	}
	for _, member := range links.DistinguishedNames {
		if err := context.Cause(ctx); err != nil {
			return false, err
		}
		parsed, err := InternalParseIdentityDN(member)
		if err != nil {
			return false, err
		}
		matches := InternalSameIdentityDN(parsed, target)
		if err := context.Cause(ctx); err != nil {
			return false, err
		}
		if matches {
			return true, nil
		}
	}
	return false, context.Cause(ctx)
}
