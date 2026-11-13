package activedirectory

import "errors"

func hasLDAPCode(err error, code uint32) bool {
	if err == nil {
		return false
	}
	if native, ok := err.(*LDAPError); ok {
		return native.Code == code
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if hasLDAPCode(child, code) {
				return true
			}
		}
	}
	return hasLDAPCode(errors.Unwrap(err), code)
}
