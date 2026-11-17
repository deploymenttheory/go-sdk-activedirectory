package acceptance

import (
	"errors"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func InternalHasLDAPCode(err error, code uint32) bool {
	if err == nil {
		return false
	}
	if native, ok := err.(*admodel.LDAPError); ok {
		return native.Code == code
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if InternalHasLDAPCode(child, code) {
				return true
			}
		}
	}
	return InternalHasLDAPCode(errors.Unwrap(err), code)
}
