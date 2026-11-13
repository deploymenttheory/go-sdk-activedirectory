//go:build windows && (amd64 || arm64)

package activedirectory

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
)

// Exercise the shared native builder with the exact optional-feature operation,
// including UTF-8 scope octets across a forced GC and response ownership.
func TestOptionalFeatureNativeUTF8OperationAndOwnership(t *testing.T) {
	for _, attribute := range []string{"enableOptionalFeature", "disableOptionalFeature"} {
		payload := []byte("CN=Partitions,CN=Configuration,DC=Dŵr,DC=test:" + optionalTestGUID)
		session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
		session.api.find = func(*win32.Proc) error { return nil }
		session.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
		session.api.result = func(_ *ldap.LDAP, id, all uint32, _ *ldap.LDAP_TIMEVAL, message **ldap.LDAPMessage) uint32 {
			if id != 17 || all != ldap.LDAP_MSG_ALL {
				t.Fatal("wrong response ownership")
			}
			*message = new(ldap.LDAPMessage)
			return uint32(ldap.LDAP_RES_MODIFY)
		}
		session.api.parseResult = func(_ *ldap.LDAP, _ *ldap.LDAPMessage, code *uint32, _, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, free foundation.BOOLEAN) uint32 {
			if free != 0 {
				t.Fatal("parser unexpectedly owns message")
			}
			*code = 0
			return 0
		}
		frees := 0
		session.api.messageFree = func(*ldap.LDAPMessage) uint32 { frees++; return 0 }
		attempt := session.ldapModifyWith(context.Background(), "", []ldapModification{{operation: 0, attribute: attribute, value: payload}}, func(_ *ldap.LDAP, dn string, mods **ldap.LDAPModW, server, client **ldap.LDAPControlW, id *uint32) uint32 {
			runtime.GC()
			pointers := unsafe.Slice(mods, 2)
			mod := pointers[0]
			name, err := copyLDAPText(mod.Mod_type)
			values := unsafe.Slice(*(***ldap.LDAP_BERVAL)(unsafe.Pointer(&mod.Mod_vals)), 2)
			if dn != "" || server != nil || client != nil || pointers[1] != nil || err != nil || name != attribute || mod.Mod_op != ldap.LDAP_MOD_BVALUES || values[1] != nil {
				t.Fatal("wrong rootDSE ADD native representation")
			}
			actual := unsafe.Slice((*byte)(unsafe.Pointer(values[0].Bv_val)), int(values[0].Bv_len))
			if !bytes.Equal(actual, payload) {
				t.Fatalf("UTF-8 octets changed: %x", actual)
			}
			*id = 17
			return 0
		})
		if attempt.State != ldapWriteAccepted || attempt.Err != nil || frees != 1 {
			t.Fatalf("attempt=%+v frees=%d", attempt, frees)
		}
	}
}

// Actual WinLDAP parses/copies/frees range responses over a loopback responder.
// This is native transport/ownership coverage, not AD authentication evidence.
func TestOptionalFeatureNativeRangeResponsesAndErrors(t *testing.T) {
	for _, mode := range []string{"complete", "native-denied", "public-base-stays-incomplete"} {
		t.Run(mode, func(t *testing.T) {
			pages := []searchWirePage{
				{count: 1, baseRead: true, omitControl: true, attributes: optionalScopeRangeObject("msds-enabledfeaturebl;range=0-0", "CN=Scope0")},
				{count: 1, baseRead: true, omitControl: true, attributes: optionalScopeRangeObject("msds-enabledfeaturebl;range=1-*", "CN=Scope1")},
			}
			pages[0].attributes["msds-enabledfeaturebl"] = [][]byte{} // un-ranged request's empty placeholder
			if mode == "native-denied" {
				pages[1].code = 50
			}
			fixture := newSearchWireFixture(t, pages)
			var counts searchNativeCounts
			client := searchWireClient(t, fixture, countedSearchAPI(&counts))
			client.config.Timeout = 5 * time.Second
			session := client.session.(*ldapSession)
			session.timeout = 5 * time.Second
			if mode == "public-base-stays-incomplete" {
				_, err := session.baseObject(context.Background(), optionalTestDN, []string{"msDS-EnabledFeatureBL"})
				if !errors.Is(err, ErrIncompleteResult) {
					t.Fatal("public base read silently accepted a range", err)
				}
			} else {
				_, object := optionalFeatureFixture()
				feature, err := decodeOptionalFeature(object)
				if err != nil {
					t.Fatal(err)
				}
				err = client.read(context.Background(), func(ctx context.Context) error { return readOptionalFeatureScopes(ctx, session, &feature) })
				if mode == "complete" {
					if err != nil || feature.EnabledScopesState != AttributePresent || len(feature.EnabledScopes) != 2 {
						t.Fatalf("state=%d values=%v err=%v", feature.EnabledScopesState, feature.EnabledScopes, err)
					}
				} else if !hasLDAPCode(err, 50) || feature.EnabledScopesState != AttributePartial || len(feature.EnabledScopes) == 0 {
					t.Fatalf("native failure masked: %+v %v", feature, err)
				}
				if len(feature.EnabledScopeObjects) != 2 {
					t.Fatal("native raw response lost")
				}
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("native range allocation leak: %+v", counts)
			}
		})
	}
}
