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

func TestNativeBaseAndTLSParserTextOwnership(t *testing.T) {
	for _, operation := range []string{"base", "tls"} {
		for _, failure := range []string{"failed-parser", "malformed", "unterminated"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				units := []uint16{0xd800, 0}
				if failure == "unterminated" {
					units = make([]uint16, 4096)
					for i := range units {
						units[i] = 'x'
					}
				}
				freedNames, freedMessages := 0, 0
				matchedUnits := append([]uint16(nil), units...)
				s := &adengine.InternalLdapSession{
					InternalHandle: new(ldap.LDAP),
					InternalApi: adengine.InternalLdapAPI{
						InternalParseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, matched, diagnostic *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
							*code = 53
							*matched, *diagnostic = &matchedUnits[0], &units[0]
							if failure == "failed-parser" {
								return 84
							}
							return 0
						},
						InternalMemoryFree: func(foundation.PWSTR) { freedNames++ },
						InternalMessageFree: func(*ldap.LDAPMessage) uint32 {
							if freedNames != 2 {
								t.Fatal("message released before parser-owned text")
							}
							freedMessages++
							return 82
						},
						InternalCountEntries: func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 },
					},
				}
				var err error
				if operation == "base" {
					_, err = s.InternalReadMessage(new(ldap.LDAPMessage))
				} else {
					err = s.InternalReadTLSResponse(new(ldap.LDAPMessage))
				}
				if failure == "failed-parser" {
					if !InternalHasLDAPCode(err, 84) || InternalHasLDAPCode(err, 53) ||
						errors.Is(err, admodel.ErrInvalidResult) {
						t.Fatalf("failed outputs were trusted or decoded: %v", err)
					}
				} else if !InternalHasLDAPCode(err, 53) || !errors.Is(err, admodel.ErrInvalidResult) {
					t.Fatalf("server status or text error lost: %v", err)
				}
				if !InternalHasLDAPCode(err, 82) || freedNames != 2 || freedMessages != 1 {
					t.Fatalf(
						"cleanup ownership/status lost: names=%d messages=%d error=%v",
						freedNames,
						freedMessages,
						err,
					)
				}
			})
		}
	}
}
