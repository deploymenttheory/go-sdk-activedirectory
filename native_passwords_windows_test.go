//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/authentication/identity"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/security/credentials"
)

func TestNativePasswordSASLProtectionAndOwnership(t *testing.T) {
	for _, mode := range []string{"strong", "unsealed", "no context", "option error", "unsupported", "flags error", "no confidentiality", "key error", "weak", "cleanup error"} {
		t.Run(mode, func(t *testing.T) {
			contextHandle := credentials.SecHandle{DwLower: 1, DwUpper: 2}
			algorithmA, algorithmB := new(uint16), new(uint16)
			freed, queries := 0, 0
			injected := errors.New("synthetic native failure")
			session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
			session.api.getOption = func(_ *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
				if mode == "option error" {
					return 82
				}
				switch uint32(option) {
				case ldap.LDAP_OPT_ENCRYPT:
					if mode != "unsealed" {
						*(*uint32)(value) = 1
					}
				case ldap.LDAP_OPT_SECURITY_CONTEXT:
					if mode != "no context" {
						*(*credentials.SecHandle)(value) = contextHandle
					}
				default:
					t.Fatal("unexpected security query")
				}
				return 0
			}
			api := passwordSecurityAPI{find: func(*win32.Proc) error {
				if mode == "unsupported" {
					return injected
				}
				return nil
			}, query: func(handle *credentials.SecHandle, attribute identity.SECPKG_ATTR, value unsafe.Pointer) error {
				queries++
				if *handle != contextHandle {
					t.Fatal("security context was not borrowed")
				}
				switch attribute {
				case identity.SECPKG_ATTR_FLAGS:
					if mode == "flags error" {
						return injected
					}
					if mode != "no confidentiality" {
						(*identity.SecPkgContext_Flags)(value).Flags = identity.ISC_RET_CONFIDENTIALITY
					}
				case identity.SECPKG_ATTR_KEY_INFO:
					if mode == "key error" {
						return injected
					}
					info := (*identity.SecPkgContext_KeyInfoW)(value)
					info.KeySize = 128
					if mode == "weak" {
						info.KeySize = 56
					}
					info.SSignatureAlgorithmName, info.SEncryptAlgorithmName = algorithmA, algorithmB
				default:
					t.Fatal("queried secret key material")
				}
				return nil
			}, free: func(pointer unsafe.Pointer) error {
				if pointer != unsafe.Pointer(algorithmA) && pointer != unsafe.Pointer(algorithmB) {
					t.Fatal("freed borrowed security context")
				}
				freed++
				if mode == "cleanup error" {
					return injected
				}
				return nil
			}}
			protection, err := session.passwordProtectionWith(context.Background(), TransportLDAP, api)
			if mode == "strong" {
				if err != nil || protection.CipherBits != 128 || freed != 2 || queries != 2 {
					t.Fatal(protection, err, freed, queries)
				}
			} else if err == nil {
				t.Fatal("unverified SASL protection accepted")
			}
			if (mode == "weak" || mode == "cleanup error") && freed != 2 {
				t.Fatal("SSPI metadata leaked")
			}
		})
	}
}

func TestNativePasswordTLSRequiresNegotiatedProtection(t *testing.T) {
	for _, transport := range []Transport{TransportLDAPS, TransportStartTLS} {
		for _, mode := range []string{"strong", "weak", "legacy", "manual certificate", "option error"} {
			t.Run(mode, func(t *testing.T) {
				session := &ldapSession{handle: new(ldap.LDAP)}
				session.api.getOption = func(_ *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
					if mode == "option error" {
						return 82
					}
					switch uint32(option) {
					case ldap.LDAP_OPT_SSL:
						*(*uint32)(value) = 1
					case ldap.LDAP_OPT_SCH_FLAGS:
						*(*uint32)(value) = schannelFlags
						if mode == "manual certificate" {
							*(*uint32)(value) |= uint32(identity.SCH_CRED_MANUAL_CRED_VALIDATION)
						}
					case ldap.LDAP_OPT_SSL_INFO:
						info := (*identity.SecPkgContext_ConnectionInfo)(value)
						info.DwProtocol = identity.SP_PROT_TLS1_2_CLIENT
						info.DwCipherStrength = 256
						if mode == "weak" {
							info.DwCipherStrength = 56
						}
						if mode == "legacy" {
							info.DwProtocol = identity.SP_PROT_TLS1_CLIENT
						}
					default:
						t.Fatal("unexpected TLS query")
					}
					return 0
				}
				protection, err := session.passwordProtectionWith(context.Background(), transport, passwordSecurityAPI{})
				if mode == "strong" {
					if err != nil || protection.CipherBits != 256 || protection.Transport != transport {
						t.Fatal(protection, err)
					}
				} else if !errors.Is(err, ErrPasswordProtection) {
					t.Fatal("unverified TLS accepted", err)
				}
			})
		}
	}
}

// These public, synthetic password fixtures test the real WinLDAP encoder on
// loopback only. The production protected-session checks are tested separately;
// no account, directory, bind credential or secret-bearing capture is involved.
func TestNativePasswordWireQuotedValuesAreNotDoubleBEREncoded(t *testing.T) {
	for _, change := range []bool{true, false} {
		oldValue, newValue := quotedPasswordUTF16([]byte("PUBLIC-old-李")), quotedPasswordUTF16([]byte("PUBLIC-new-😀\""))
		defer erasePasswordBuffer(oldValue)
		defer erasePasswordBuffer(newValue)
		modification := func(operation byte, value []byte) []byte {
			return searchBER(0x30, []byte{10, 1, operation}, searchBER(0x30, searchBER(4, []byte("unicodePwd")), searchBER(0x31, searchBER(4, value))))
		}
		mods := []ldapAttributeModification{{operation: 2, attribute: "unicodePwd", values: [][]byte{newValue}}}
		body := searchBER(0x30, modification(2, newValue))
		if change {
			mods = []ldapAttributeModification{{operation: 1, attribute: "unicodePwd", values: [][]byte{oldValue}}, {operation: 0, attribute: "unicodePwd", values: [][]byte{newValue}}}
			body = searchBER(0x30, modification(1, oldValue), modification(0, newValue))
		}
		dn := objectGUIDTarget(objectTestGUID())
		fixture := newWriteWireFixture(t, 0x66, 0x67, append(searchBER(4, []byte(dn)), body...), nil, 0)
		var counts searchNativeCounts
		client := searchWireClient(t, &searchWireFixture{listener: fixture.listener}, countedSearchAPI(&counts))
		var attempt ldapWriteAttempt
		err := client.read(context.Background(), func(ctx context.Context) error {
			attempt = client.session.(*ldapSession).ldapWrite(ctx, ldapWriteRequest{operation: ldapWriteModify, dn: dn, modifications: mods})
			return attempt.Err
		})
		if err != nil || attempt.State != ldapWriteAccepted {
			t.Fatal(attempt.State, err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if counts != (searchNativeCounts{}) {
			t.Fatal("native allocation leak")
		}
	}
}
