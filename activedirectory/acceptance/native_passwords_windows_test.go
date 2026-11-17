//go:build windows && (amd64 || arm64)

package acceptance

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
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestNativePasswordSASLProtectionAndOwnership(t *testing.T) {
	for _, mode := range []string{"strong", "unsealed", "no context", "option error", "unsupported", "flags error", "no confidentiality", "key error", "weak", "cleanup error"} {
		t.Run(mode, func(t *testing.T) {
			contextHandle := credentials.SecHandle{DwLower: 1, DwUpper: 2}
			algorithmA, algorithmB := new(uint16), new(uint16)
			freed, queries := 0, 0
			injected := errors.New("synthetic native failure")
			session := &adengine.InternalLdapSession{
				InternalHandle:  new(ldap.LDAP),
				InternalTimeout: time.Second,
			}
			session.InternalApi.InternalGetOption = func(_ *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
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
			api := adengine.InternalPasswordSecurityAPI{InternalFind: func(*win32.Proc) error {
				if mode == "unsupported" {
					return injected
				}
				return nil
			}, InternalQuery: func(handle *credentials.SecHandle, attribute identity.SECPKG_ATTR, value unsafe.Pointer) error {
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
			}, InternalFree: func(pointer unsafe.Pointer) error {
				if pointer != unsafe.Pointer(algorithmA) && pointer != unsafe.Pointer(algorithmB) {
					t.Fatal("freed borrowed security context")
				}
				freed++
				if mode == "cleanup error" {
					return injected
				}
				return nil
			}}
			protection, err := session.InternalPasswordProtectionWith(
				context.Background(),
				admodel.TransportLDAP,
				api,
			)
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
	for _, transport := range []admodel.Transport{admodel.TransportLDAPS, admodel.TransportStartTLS} {
		for _, mode := range []string{"strong", "weak", "legacy", "manual certificate", "option error"} {
			t.Run(mode, func(t *testing.T) {
				session := &adengine.InternalLdapSession{InternalHandle: new(ldap.LDAP)}
				session.InternalApi.InternalGetOption = func(_ *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
					if mode == "option error" {
						return 82
					}
					switch uint32(option) {
					case ldap.LDAP_OPT_SSL:
						*(*uint32)(value) = 1
					case ldap.LDAP_OPT_SCH_FLAGS:
						*(*uint32)(value) = adengine.InternalSchannelFlags
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
				protection, err := session.InternalPasswordProtectionWith(
					context.Background(),
					transport,
					adengine.InternalPasswordSecurityAPI{},
				)
				if mode == "strong" {
					if err != nil || protection.CipherBits != 256 ||
						protection.Transport != transport {
						t.Fatal(protection, err)
					}
				} else if !errors.Is(err, admodel.ErrPasswordProtection) {
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
		oldValue, newValue := admodel.InternalQuotedPasswordUTF16(
			[]byte("PUBLIC-old-李"),
		), admodel.InternalQuotedPasswordUTF16(
			[]byte("PUBLIC-new-😀\""),
		)
		defer admodel.InternalErasePasswordBuffer(oldValue)
		defer admodel.InternalErasePasswordBuffer(newValue)
		modification := func(operation byte, value []byte) []byte {
			return InternalSearchBER(
				0x30,
				[]byte{10, 1, operation},
				InternalSearchBER(
					0x30,
					InternalSearchBER(4, []byte("unicodePwd")),
					InternalSearchBER(0x31, InternalSearchBER(4, value)),
				),
			)
		}
		mods := []admodel.InternalLdapAttributeModification{
			{
				InternalOperation: 2,
				InternalAttribute: "unicodePwd",
				InternalValues:    [][]byte{newValue},
			},
		}
		body := InternalSearchBER(0x30, modification(2, newValue))
		if change {
			mods = []admodel.InternalLdapAttributeModification{
				{
					InternalOperation: 1,
					InternalAttribute: "unicodePwd",
					InternalValues:    [][]byte{oldValue},
				},
				{
					InternalOperation: 0,
					InternalAttribute: "unicodePwd",
					InternalValues:    [][]byte{newValue},
				},
			}
			body = InternalSearchBER(0x30, modification(1, oldValue), modification(0, newValue))
		}
		dn := admodel.InternalObjectGUIDTarget(InternalObjectTestGUID())
		fixture := InternalNewWriteWireFixture(
			t,
			0x66,
			0x67,
			append(InternalSearchBER(4, []byte(dn)), body...),
			nil,
			0,
		)
		var counts InternalSearchNativeCounts
		client := InternalSearchWireClient(
			t,
			&InternalSearchWireFixture{InternalListener: fixture.InternalListener},
			InternalCountedSearchAPI(&counts),
		)
		var attempt admodel.InternalLdapWriteAttempt
		err := adengine.InternalClientRead(
			client,
			context.Background(),
			func(ctx context.Context) error {
				attempt = adengine.InternalClientSession(client).(*adengine.InternalLdapSession).InternalLdapWrite(
					ctx,
					admodel.InternalLdapWriteRequest{
						InternalOperation:     admodel.InternalLdapWriteModify,
						InternalDn:            dn,
						InternalModifications: mods,
					},
				)
				return attempt.Err
			},
		)
		if err != nil || attempt.State != admodel.InternalLdapWriteAccepted {
			t.Fatal(attempt.State, err)
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}
		if counts != (InternalSearchNativeCounts{}) {
			t.Fatal("native allocation leak")
		}
	}
}
