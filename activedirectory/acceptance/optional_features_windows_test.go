//go:build windows && (amd64 || arm64)

package acceptance

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// Exercise the shared native builder with the exact optional-feature operation,
// including UTF-8 scope octets across a forced GC and response ownership.
func TestOptionalFeatureNativeUTF8OperationAndOwnership(t *testing.T) {
	for _, attribute := range []string{"enableOptionalFeature", "disableOptionalFeature"} {
		payload := []byte(
			"CN=Partitions,CN=Configuration,DC=Dŵr,DC=test:" + InternalOptionalTestGUID,
		)
		session := &adengine.InternalLdapSession{
			InternalHandle:  new(ldap.LDAP),
			InternalTimeout: time.Second,
		}
		session.InternalApi.InternalFind = func(*win32.Proc) error { return nil }
		session.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
		session.InternalApi.InternalResult = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
			if id != 17 || all != ldap.LDAP_MSG_ALL {
				t.Fatal("wrong response ownership")
			}
			*message = new(ldap.LDAPMessage)
			return uint32(ldap.LDAP_RES_MODIFY)
		}
		session.InternalApi.InternalParseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
			if free != 0 {
				t.Fatal("parser unexpectedly owns message")
			}
			*code = 0
			return 0
		}
		frees := 0
		session.InternalApi.InternalMessageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
		attempt := session.InternalLdapModifyWith(
			context.Background(),
			"",
			[]admodel.InternalLdapModification{
				{InternalOperation: 0, InternalAttribute: attribute, InternalValue: payload},
			},
			func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, id *uint32) uint32 {
				runtime.GC()
				pointers := unsafe.Slice(mods, 2)
				mod := pointers[0]
				name, err := adengine.InternalCopyLDAPText(mod.Mod_type)
				values := unsafe.Slice(*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&mod.Mod_vals)), 2)
				if dn != "" || server != nil || client != nil || pointers[1] != nil || err != nil ||
					name != attribute ||
					mod.Mod_op != ldap.LDAP_MOD_BVALUES ||
					values[1] != nil {
					t.Fatal("wrong rootDSE ADD native representation")
				}
				actual := unsafe.Slice(
					(*byte)(unsafe.Pointer(values[0].Bv_val)),
					int(values[0].Bv_len),
				)
				if !bytes.Equal(actual, payload) {
					t.Fatalf("UTF-8 octets changed: %x", actual)
				}
				*id = 17
				return 0
			},
		)
		if attempt.State != admodel.InternalLdapWriteAccepted || attempt.Err != nil || frees != 1 {
			t.Fatalf("attempt=%+v frees=%d", attempt, frees)
		}
	}
}

// Actual WinLDAP parses/copies/frees range responses over a loopback responder.
// This is native transport/ownership coverage, not AD authentication evidence.
func TestOptionalFeatureNativeRangeResponsesAndErrors(t *testing.T) {
	for _, mode := range []string{"complete", "native-denied", "public-base-stays-incomplete"} {
		t.Run(mode, func(t *testing.T) {
			pages := []InternalSearchWirePage{
				{
					InternalCount:       1,
					InternalBaseRead:    true,
					InternalOmitControl: true,
					InternalAttributes: InternalOptionalScopeRangeObject(
						"msds-enabledfeaturebl;range=0-0",
						"CN=Scope0",
					),
				},
				{
					InternalCount:       1,
					InternalBaseRead:    true,
					InternalOmitControl: true,
					InternalAttributes: InternalOptionalScopeRangeObject(
						"msds-enabledfeaturebl;range=1-*",
						"CN=Scope1",
					),
				},
			}
			pages[0].InternalAttributes["msds-enabledfeaturebl"] = [][]byte{} // un-ranged request's empty placeholder
			if mode == "native-denied" {
				pages[1].InternalCode = 50
			}
			fixture := InternalNewSearchWireFixture(t, pages)
			var counts InternalSearchNativeCounts
			client := InternalSearchWireClient(t, fixture, InternalCountedSearchAPI(&counts))
			(*adengine.InternalClientConfigPointer(client)).Timeout = 5 * time.Second
			session := adengine.InternalClientSession(client).(*adengine.InternalLdapSession)
			session.InternalTimeout = 5 * time.Second
			if mode == "public-base-stays-incomplete" {
				_, err := session.InternalBaseObject(
					context.Background(),
					InternalOptionalTestDN,
					[]string{"msDS-EnabledFeatureBL"},
				)
				if !errors.Is(err, admodel.ErrIncompleteResult) {
					t.Fatal("public base read silently accepted a range", err)
				}
			} else {
				_, object := InternalOptionalFeatureFixture()
				feature, err := admodel.InternalDecodeOptionalFeature(object)
				if err != nil {
					t.Fatal(err)
				}
				err = adengine.InternalClientRead(
					client,
					context.Background(),
					func(ctx context.Context) error {
						return admodel.InternalReadOptionalFeatureScopes(ctx, session, &feature)
					},
				)
				if mode == "complete" {
					if err != nil || feature.EnabledScopesState != admodel.AttributePresent ||
						len(feature.EnabledScopes) != 2 {
						t.Fatalf(
							"state=%d values=%v err=%v",
							feature.EnabledScopesState,
							feature.EnabledScopes,
							err,
						)
					}
				} else if !InternalHasLDAPCode(err, 50) || feature.EnabledScopesState != admodel.AttributePartial || len(feature.EnabledScopes) == 0 {
					t.Fatalf("native failure masked: %+v %v", feature, err)
				}
				if len(feature.EnabledScopeObjects) != 2 {
					t.Fatal("native raw response lost")
				}
			}
			if counts != (InternalSearchNativeCounts{}) {
				t.Fatalf("native range allocation leak: %+v", counts)
			}
		})
	}
}
