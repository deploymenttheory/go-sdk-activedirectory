//go:build windows && (amd64 || arm64)

package acceptance

import (
	"errors"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Base-object reads and StartTLS share response parsing after the prerequisites
// are merged. Failed parsing must release its output strings without reading
// them or trusting the unconfirmed server status.
func TestResponseParsingBoundsStringsAndReleasesFailedOutputs(t *testing.T) {
	for _, parseFails := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "malformed-success", true: "failed-parse"}[parseFails],
			func(t *testing.T) {
				matched, diagnostic := []uint16{0xd800, 0}, []uint16{0xdc00, 0}
				released := map[foundation.PWSTR]int{}
				session := adengine.InternalLdapSession{
					InternalHandle: new(ldap.LDAP),
					InternalApi: adengine.InternalLdapAPI{
						InternalParseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, dn, detail *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
							*code = 53
							*dn, *detail = &matched[0], &diagnostic[0]
							if parseFails {
								return 84
							}
							return 0
						},
						InternalMemoryFree: func(p foundation.PWSTR) { released[p]++ },
					},
				}
				err := session.InternalParseResponse(new(ldap.LDAPMessage), "test")
				if released[&matched[0]] != 1 || released[&diagnostic[0]] != 1 ||
					len(released) != 2 {
					t.Fatal("response strings were not each released exactly once")
				}
				wantServerStatus := !parseFails
				if InternalHasLDAPCode(err, 53) != wantServerStatus ||
					InternalHasLDAPCode(err, 84) != parseFails ||
					errors.Is(err, admodel.ErrInvalidResult) == parseFails {
					t.Fatalf("parse/status/decode errors: %v", err)
				}
			},
		)
	}
}
