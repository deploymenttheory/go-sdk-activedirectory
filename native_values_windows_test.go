//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"math"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

// The fake native boundary poisons each borrowed buffer on release. Returned Go
// values must remain correct, and every allocated token must be released once,
// including result strings, enumeration cursors, and partial-result failures.
func TestNativeRootDSECopiesValuesAndReleasesEveryOwner(t *testing.T) {
	for _, fail := range []string{"none", "server-error", "parse-error", "count-error", "result-error", "value-free", "message-free", "nil-cursor", "bad-value"} {
		t.Run(fail, func(t *testing.T) {
			owned := map[unsafe.Pointer]string{}
			track := func(pointer unsafe.Pointer, kind string) {
				if _, ok := owned[pointer]; ok {
					t.Fatalf("duplicate allocation %s", kind)
				}
				owned[pointer] = kind
			}
			free := func(pointer unsafe.Pointer) {
				if _, ok := owned[pointer]; !ok {
					t.Fatalf("unowned or double free %p", pointer)
				}
				delete(owned, pointer)
			}
			message := new(ldap.LDAPMessage)
			cursor := new(ldap.BerElement)
			track(unsafe.Pointer(message), "message")
			attributeNames := []string{"dnsHostName", "vendor-binary", "vendor-empty"}
			payloads := [][]byte{[]byte("dc1.ad.sdk.test"), {0, 0xff, 7}, {}}
			attributeIndex := 0
			allocateString := func(value string) foundation.PWSTR {
				p := win32.UTF16Ptr(value)
				track(unsafe.Pointer(p), "string")
				return p
			}
			var nativeValues []*ldap.LDAP_BERVAL
			api := ldapAPI{
				parseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, matched, diagnostic *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
					*matched = allocateString("DC=ad,DC=sdk,DC=test")
					*diagnostic = allocateString("retained private diagnostic")
					if fail == "server-error" {
						*code = 3
					}
					if fail == "parse-error" {
						return 84
					}
					return 0
				},
				messageFree: func(p *ldap.LDAPMessage) uint32 {
					free(unsafe.Pointer(p))
					if fail == "message-free" {
						return 80
					}
					return 0
				},
				memoryFree: func(p foundation.PWSTR) { free(unsafe.Pointer(p)) },
				countEntries: func(*ldap.LDAP, *ldap.LDAPMessage) uint32 {
					if fail == "count-error" {
						return math.MaxUint32
					}
					return 1
				},
				firstEntry: func(*ldap.LDAP, *ldap.LDAPMessage) *ldap.LDAPMessage { return message },
				firstAttribute: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, out **ldap.BerElement) foundation.PWSTR {
					if fail != "nil-cursor" {
						*out = cursor
						track(unsafe.Pointer(cursor), "cursor")
					}
					return allocateString(attributeNames[0])
				},
				nextAttribute: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, p *ldap.BerElement) foundation.PWSTR {
					if p != cursor {
						t.Fatal("wrong cursor")
					}
					attributeIndex++
					if attributeIndex == len(attributeNames) {
						return nil
					}
					return allocateString(attributeNames[attributeIndex])
				},
				berFree: func(p *ldap.BerElement, freeBuffer int32) {
					if freeBuffer != 0 {
						t.Fatal("cursor must not free borrowed message buffer")
					}
					free(unsafe.Pointer(p))
				},
				values: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, _ string) **ldap.LDAP_BERVAL {
					payload := payloads[attributeIndex]
					value := &ldap.LDAP_BERVAL{Bv_len: uint32(len(payload))}
					if len(payload) > 0 && fail != "bad-value" {
						value.Bv_val = (*byte)(unsafe.Pointer(&payload[0]))
					}
					nativeValues = []*ldap.LDAP_BERVAL{value, nil}
					track(unsafe.Pointer(&nativeValues[0]), "values")
					return &nativeValues[0]
				},
				countValues: func(**ldap.LDAP_BERVAL) uint32 { return 1 },
				valuesFree: func(p **ldap.LDAP_BERVAL) uint32 {
					free(unsafe.Pointer(p))
					clear(payloads[attributeIndex])
					if fail == "value-free" {
						return 80
					}
					return 0
				},
				getOption: func(_ *ldap.LDAP, _ int32, out unsafe.Pointer) uint32 {
					*(*uint32)(out) = 0
					if fail == "count-error" || fail == "result-error" {
						*(*uint32)(out) = 81
					}
					return 0
				},
				result: func(_ *ldap.LDAP, _ uint32, _ uint32, _ *ldap.LDAP_TIMEVAL, out **ldap.LDAPMessage) uint32 {
					*out = message
					return math.MaxUint32
				},
				abandon: func(*ldap.LDAP, uint32) uint32 { return 0 },
			}
			session := &ldapSession{handle: new(ldap.LDAP), api: api}
			var attributes map[string][][]byte
			var err error
			if fail == "result-error" {
				attributes, err = session.waitRootDSE(context.Background(), 7)
			} else {
				attributes, err = session.readMessage(message)
			}
			if len(owned) != 0 {
				t.Fatalf("unreleased owners: %v", owned)
			}
			if fail == "none" {
				if err != nil {
					t.Fatal(err)
				}
				if string(attributes["dnshostname"][0]) != "dc1.ad.sdk.test" || !bytes.Equal(attributes["vendor-binary"][0], []byte{0, 0xff, 7}) || len(attributes["vendor-empty"]) != 1 || attributes["vendor-empty"][0] == nil {
					t.Fatal("copied binary/string/empty values changed after native release")
				}
			} else if err == nil {
				t.Fatal("injected failure disappeared")
			}
			if fail == "server-error" && (!hasLDAPCode(err, 3) || len(attributes) != 3) {
				t.Fatalf("partial server result lost: %v", err)
			}
			if fail == "parse-error" && (!hasLDAPCode(err, 84) || len(attributes) != 3) {
				t.Fatalf("partial parse failure lost: %v", err)
			}
			if fail == "count-error" && !hasLDAPCode(err, 81) {
				t.Fatalf("native count failure lost: %v", err)
			}
			if fail == "result-error" && (!hasLDAPCode(err, 81) || len(attributes) != 3) {
				t.Fatalf("partial transport failure lost: %v", err)
			}
		})
	}
}
