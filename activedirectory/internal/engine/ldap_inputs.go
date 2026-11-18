package engine

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// InternalValidateLDAPWrite applies the common native/portable input contract
// before either backend can submit a mutation or construct unmanaged buffers.
func InternalValidateLDAPWrite(request admodel.InternalLdapWriteRequest) error {
	if request.InternalOperation > admodel.InternalLdapWriteRename ||
		!utf8.ValidString(request.InternalDn) ||
		strings.ContainsRune(request.InternalDn, 0) {
		return admodel.ErrInvalidResult
	}
	if request.InternalOperation != admodel.InternalLdapWriteModify && request.InternalDn == "" {
		return admodel.ErrInvalidResult
	}
	if request.InternalOperation == admodel.InternalLdapWriteRename {
		if request.InternalNewRDN == "" || !utf8.ValidString(request.InternalNewRDN) ||
			strings.ContainsRune(request.InternalNewRDN, 0) {
			return admodel.ErrInvalidResult
		}
		if !utf8.ValidString(request.InternalNewParent) ||
			strings.ContainsRune(request.InternalNewParent, 0) {
			return admodel.ErrInvalidResult
		}
	} else if request.InternalNewRDN != "" || request.InternalNewParent != "" || request.InternalDeleteOldRDN {
		return admodel.ErrInvalidResult
	}
	if request.InternalOperation == admodel.InternalLdapWriteAdd ||
		request.InternalOperation == admodel.InternalLdapWriteModify {
		if len(request.InternalModifications) == 0 {
			return admodel.ErrInvalidResult
		}
	} else if len(
		request.InternalModifications,
	) != 0 {
		return admodel.ErrInvalidResult
	}
	for _, mod := range request.InternalModifications {
		if err := internalValidateLDAPModification(request.InternalOperation, mod); err != nil {
			return err
		}
	}
	for _, control := range request.InternalControls {
		if !InternalValidLDAPWriteOID(control.InternalOid) ||
			uint64(len(control.InternalValue)) > math.MaxUint32 {
			return admodel.ErrInvalidResult
		}
	}
	return nil
}

func internalValidateLDAPModification(operation admodel.InternalLdapWriteOperation, mod admodel.InternalLdapAttributeModification) error {
	if !admodel.InternalAttributeDescription.MatchString(mod.InternalAttribute) || mod.InternalOperation > 2 ||
		(operation == admodel.InternalLdapWriteAdd && mod.InternalOperation != 0) ||
		(len(mod.InternalValues) == 0 && mod.InternalOperation != 1) {
		return admodel.ErrInvalidResult
	}
	for _, value := range mod.InternalValues {
		if uint64(len(value)) > math.MaxUint32 {
			return admodel.ErrInvalidResult
		}
	}
	return nil
}

func InternalValidLDAPWriteOID(oid string) bool {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func InternalValidRangedAttribute(name string) bool {
	base, tail, ok := strings.Cut(strings.ToLower(name), ";range=")
	if !ok || !admodel.InternalAttributeDescription.MatchString(base) {
		return false
	}
	startText, endText, ok := strings.Cut(tail, "-")
	if !ok {
		return false
	}
	start, err := strconv.ParseUint(startText, 10, 32)
	if err != nil {
		return false
	}
	if endText == "*" {
		return true
	}
	end, err := strconv.ParseUint(endText, 10, 32)
	return err == nil && end >= start
}
