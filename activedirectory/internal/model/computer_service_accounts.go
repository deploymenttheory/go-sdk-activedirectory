package model

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

var ErrServiceAccountAssociationLimit = errors.New(
	"computer service account association limit reached",
)

const (
	InternalServiceAccountMaxLinks  = 100000
	InternalServiceAccountMaxRanges = 1000
	InternalServiceAccountMaxBytes  = 64 << 20
)

// These operations edit directory links only. They do not install an account,
// reset its password, or grant a computer permission to retrieve a gMSA secret.
type ComputerServiceAccountRequest struct {
	Computer Identity
	Accounts []Identity
	// Strict by default. Permissive asks the server to ignore existing adds or
	// absent deletes using its advertised critical permissive-modify control.
	Permissive bool
	Options    ObjectMutationOptions
}
type ComputerServiceAccountMutationResult struct {
	Mutation ObjectMutationResult
	Accounts []IdentityResult
	Links    *ComputerServiceAccountsResult
}
type ComputerServiceAccountsOptions struct {
	Partition                      string
	MaxValues, MaxRanges, MaxBytes int
}
type ComputerServiceAccountRange struct {
	Property   string
	Attributes map[string][][]byte
	Error      error
}
type ComputerServiceAccountLink struct {
	DistinguishedName string
	Account           *ServiceAccount
	Observation       IdentityResult
	Error             error
}

// Complete describes enumeration and resolution, not visibility through ACLs.
// AttributeReturned=false cannot establish that no associations exist.
type ComputerServiceAccountsResult struct {
	Computer                    IdentityResult
	Links                       []ComputerServiceAccountLink
	Ranges                      []ComputerServiceAccountRange
	Version                     *ObjectVersion
	AttributeReturned, Complete bool
}

type InternalServiceAccountRangeReader interface {
	InternalRangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
}

func InternalServiceAccountLinkVersion(object Object) (GUID, uint64, error) {
	v, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, 0, err
	}
	guid, err := v.GUID()
	if err != nil {
		return GUID{}, 0, err
	}
	v, err = object.Values("uSNChanged").Single()
	if err != nil {
		return guid, 0, err
	}
	text, err := v.Text()
	if err != nil {
		return guid, 0, err
	}
	usn, err := strconv.ParseUint(text, 10, 64)
	return guid, usn, err
}

func InternalCollectComputerServiceAccountLinks(
	ctx context.Context,
	reader InternalServiceAccountRangeReader,
	options ComputerServiceAccountsOptions,
	result *ComputerServiceAccountsResult,
) error {
	start, remaining := uint64(0), options.MaxBytes
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if len(result.Ranges) >= options.MaxRanges || len(result.Links) >= options.MaxValues {
			return ErrServiceAccountAssociationLimit
		}
		count := min(1500, options.MaxValues-len(result.Links))
		property := fmt.Sprintf("msDS-HostServiceAccount;range=%d-%d", start, start+uint64(count)-1)
		attrs, readErr := reader.InternalRangedBaseObject(
			ctx,
			InternalObjectGUIDTarget(result.Version.GUID),
			[]string{property, "objectGUID", "uSNChanged"},
		)
		result.Ranges = append(
			result.Ranges,
			ComputerServiceAccountRange{Property: property, Attributes: attrs, Error: readErr},
		)
		for name, values := range attrs {
			if cause := context.Cause(ctx); cause != nil {
				return errors.Join(readErr, cause)
			}
			if len(name) > remaining {
				return errors.Join(readErr, ErrServiceAccountAssociationLimit)
			}
			remaining -= len(name)
			for _, value := range values {
				if cause := context.Cause(ctx); cause != nil {
					return errors.Join(readErr, cause)
				}
				if len(value) > remaining {
					return errors.Join(readErr, ErrServiceAccountAssociationLimit)
				}
				remaining -= len(value)
			}
		}
		values, next, terminal, present, err := InternalDirectoryReferenceRange(
			attrs,
			"msDS-HostServiceAccount",
			start,
		)
		result.AttributeReturned = result.AttributeReturned || present
		if len(values) > options.MaxValues-len(result.Links) {
			return errors.Join(readErr, err, ErrServiceAccountAssociationLimit)
		}
		for _, value := range values {
			if cause := context.Cause(ctx); cause != nil {
				return errors.Join(readErr, err, cause)
			}
			text, e := NewRawValue(value).Text()
			if e == nil {
				_, e = IdentityByDN(text)
			}
			if e != nil {
				err = errors.Join(err, e)
				continue
			}
			result.Links = append(result.Links, ComputerServiceAccountLink{DistinguishedName: text})
		}
		guid, usn, e := InternalServiceAccountLinkVersion(Object{Attributes: attrs})
		if e == nil && (guid != result.Version.GUID || usn != result.Version.USNChanged) {
			e = ErrObjectConcurrency
		}
		if e = errors.Join(readErr, err, e); e != nil {
			return e
		}
		if terminal {
			result.Complete = true
			return nil
		}
		start = next
	}
}
