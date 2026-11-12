//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"errors"
	"testing"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
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
				s := &ldapSession{handle: new(ldap.LDAP), api: ldapAPI{
					parseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, matched, diagnostic *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
						*code = 53
						*matched, *diagnostic = &matchedUnits[0], &units[0]
						if failure == "failed-parser" {
							return 84
						}
						return 0
					},
					memoryFree: func(foundation.PWSTR) { freedNames++ },
					messageFree: func(*ldap.LDAPMessage) uint32 {
						if freedNames != 2 {
							t.Fatal("message released before parser-owned text")
						}
						freedMessages++
						return 82
					},
					countEntries: func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 },
				}}
				var err error
				if operation == "base" {
					_, err = s.readMessage(new(ldap.LDAPMessage))
				} else {
					err = s.readTLSResponse(new(ldap.LDAPMessage))
				}
				if failure == "failed-parser" {
					if !hasLDAPCode(err, 84) || hasLDAPCode(err, 53) || errors.Is(err, ErrInvalidResult) {
						t.Fatalf("failed outputs were trusted or decoded: %v", err)
					}
				} else if !hasLDAPCode(err, 53) || !errors.Is(err, ErrInvalidResult) {
					t.Fatalf("server status or text error lost: %v", err)
				}
				if !hasLDAPCode(err, 82) || freedNames != 2 || freedMessages != 1 {
					t.Fatalf("cleanup ownership/status lost: names=%d messages=%d error=%v", freedNames, freedMessages, err)
				}
			})
		}
	}
}
