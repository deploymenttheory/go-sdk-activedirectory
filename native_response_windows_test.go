//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"errors"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

// Base-object reads and StartTLS share response parsing after the prerequisites
// are merged. Failed parsing must release its output strings without reading
// them or trusting the unconfirmed server status.
func TestResponseParsingBoundsStringsAndReleasesFailedOutputs(t *testing.T) {
	for _, parseFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "malformed-success", true: "failed-parse"}[parseFails], func(t *testing.T) {
			matched, diagnostic := []uint16{0xd800, 0}, []uint16{0xdc00, 0}
			released := map[foundation.PWSTR]int{}
			session := ldapSession{handle: new(ldap.LDAP), api: ldapAPI{
				parseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, dn, detail *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
					*code = 53
					*dn, *detail = &matched[0], &diagnostic[0]
					if parseFails {
						return 84
					}
					return 0
				},
				memoryFree: func(p foundation.PWSTR) { released[p]++ },
			}}
			err := session.parseResponse(new(ldap.LDAPMessage), "test")
			if released[&matched[0]] != 1 || released[&diagnostic[0]] != 1 || len(released) != 2 {
				t.Fatal("response strings were not each released exactly once")
			}
			wantServerStatus := !parseFails
			if hasLDAPCode(err, 53) != wantServerStatus || hasLDAPCode(err, 84) != parseFails ||
				errors.Is(err, ErrInvalidResult) == parseFails {
				t.Fatalf("parse/status/decode errors: %v", err)
			}
		})
	}
}
