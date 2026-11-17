//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestNativeDialOwnershipAndSecurityOptions(t *testing.T) {
	for _, failure := range []string{"none", "missing-export", "init", "option", "connect", "bind", "bind-and-close"} {
		t.Run(failure, func(t *testing.T) {
			api := adengine.InternalSystemLDAPAPI()
			init, unbind, set := api.InternalInit, api.InternalUnbind, api.InternalSetOption
			allocations, frees, binds := 0, 0, 0
			options := make(map[int32]uint32)
			api.InternalInit = func(host string, port uint32) *ldap.LDAP {
				if failure == "init" {
					return nil
				}
				handle := init(host, port)
				if handle != nil {
					allocations++
				}
				return handle
			}
			api.InternalLastError = func() uint32 { return 90 }
			api.InternalUnbind = func(handle *ldap.LDAP) uint32 {
				frees++
				status := unbind(handle)
				if failure == "bind-and-close" {
					return 80
				}
				return status
			}
			api.InternalSetOption = func(handle *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
				options[option] = *(*uint32)(value)
				if failure == "option" && option == int32(ldap.LDAP_OPT_ENCRYPT) {
					return 53
				}
				return set(handle, option, value)
			}
			api.InternalConnect = func(_ *ldap.LDAP, timeout *ldap.LDAP_TIMEVAL) uint32 {
				if timeout.Tv_sec != 0 || timeout.Tv_usec != 250000 {
					t.Errorf("connect timeout: %+v", timeout)
				}
				if failure == "connect" {
					return 81
				}
				return 0
			}
			api.InternalBind = func(_ *ldap.LDAP, dn *string, credential foundation.PWSTR, method uint32) uint32 {
				binds++
				if dn != nil || credential != nil || method != 0x486 {
					t.Error("bind did not use current-identity Negotiate")
				}
				if failure == "bind" || failure == "bind-and-close" {
					return 49
				}
				return 0
			}
			if failure == "missing-export" {
				api.InternalFind = func(*win32.Proc) error { return errors.New("injected missing export") }
			}
			config := admodel.Config{
				Endpoint: admodel.Endpoint{Host: "dc1.ad.sdk.test", Port: 389},
				Timeout:  250 * time.Millisecond,
			}
			session, err := adengine.InternalDialWithAPI(context.Background(), config, api)
			if failure == "none" {
				if err != nil {
					t.Fatal(err)
				}
				if err := session.InternalClose(); err != nil {
					t.Fatal(err)
				}
				if err := session.InternalClose(); err != nil {
					t.Fatal(err)
				}
				for option, value := range map[uint32]uint32{ldap.LDAP_OPT_SIGN: 1, ldap.LDAP_OPT_ENCRYPT: 1, ldap.LDAP_OPT_AREC_EXCLUSIVE: 1, ldap.LDAP_OPT_AUTO_RECONNECT: 0, ldap.LDAP_OPT_REFERRALS: 0, ldap.LDAP_OPT_ROOTDSE_CACHE: 0, ldap.LDAP_OPT_SEND_TIMEOUT: 1, ldap.LDAP_OPT_TIMELIMIT: 1} {
					if got, found := options[int32(option)]; !found || got != value {
						t.Errorf("option %d=%d, found=%v", option, got, found)
					}
				}
				if binds != 1 {
					t.Fatal("bind count", binds)
				}
			} else {
				if err == nil || session != nil {
					t.Fatalf("injected failure returned %v, %v", session, err)
				}
				if failure == "missing-export" && !errors.Is(err, admodel.ErrUnsupported) {
					t.Fatalf("missing export: %v", err)
				}
				if failure == "bind-and-close" &&
					(!InternalHasLDAPCode(err, 49) || !InternalHasLDAPCode(err, 80)) {
					t.Fatalf("lost operation or cleanup status: %v", err)
				}
			}
			if allocations != frees {
				t.Fatalf("allocated %d, freed %d", allocations, frees)
			}
		})
	}
}

func TestNativeResultFailureFreesMessageBeforeAbandon(t *testing.T) {
	message := new(ldap.LDAPMessage)
	var order []string
	session := &adengine.InternalLdapSession{
		InternalHandle: new(ldap.LDAP),
		InternalApi: adengine.InternalLdapAPI{
			InternalParseResult: func(_ *ldap.LDAP, _ *ldap.LDAPMessage, _ *uint32, _ *foundation.PWSTR, _ *foundation.PWSTR, _ ***uint16, _ ***ldap.LDAPControlW, _ foundation.BOOLEAN) uint32 {
				return 84
			},
			InternalCountEntries: func(*ldap.LDAP, *ldap.LDAPMessage) uint32 { return 0 },
			InternalResult: func(_ *ldap.LDAP, _ uint32, all uint32, _ *ldap.LDAP_TIMEVAL, out **ldap.LDAPMessage) uint32 {
				order = append(order, "result")
				if all != ldap.LDAP_MSG_ALL {
					t.Error("must collect complete chain")
				}
				*out = message
				return math.MaxUint32
			},
			InternalGetOption: func(_ *ldap.LDAP, _ int32, out unsafe.Pointer) uint32 { *(*uint32)(out) = 81; return 0 },
			InternalMessageFree: func(got *ldap.LDAPMessage) uint32 {
				if got != message {
					t.Error("wrong message")
				}
				order = append(order, "free")
				return 0
			},
			InternalAbandon: func(_ *ldap.LDAP, id uint32) uint32 {
				if id != 7 {
					t.Error("wrong ID")
				}
				order = append(order, "abandon")
				return 0
			},
		},
	}
	_, err := session.InternalWaitRootDSE(context.Background(), 7)
	if !InternalHasLDAPCode(err, 81) || len(order) != 3 || order[0] != "result" ||
		order[1] != "free" ||
		order[2] != "abandon" {
		t.Fatalf("failure=%v order=%v", err, order)
	}
}

func TestNativeCanceledReadRetiresSessionWhenAbandonFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	frees := 0
	session := &adengine.InternalLdapSession{
		InternalHandle: new(ldap.LDAP),
		InternalApi: adengine.InternalLdapAPI{
			InternalAbandon: func(*ldap.LDAP, uint32) uint32 { return 81 },
			InternalUnbind:  func(*ldap.LDAP) uint32 { frees++; return 80 },
		},
	}
	_, err := session.InternalWaitRootDSE(ctx, 7)
	if !errors.Is(err, context.Canceled) || !InternalHasLDAPCode(err, 81) ||
		!InternalHasLDAPCode(err, 80) ||
		frees != 1 ||
		session.InternalHandle != nil {
		t.Fatalf("failure=%v frees=%d handle=%p", err, frees, session.InternalHandle)
	}
	_ = session.InternalClose()
	if frees != 1 {
		t.Fatal("double unbind")
	}
}

func TestNativeTimeoutRounding(t *testing.T) {
	for _, wait := range []time.Duration{time.Nanosecond, time.Microsecond, 999999999 * time.Nanosecond, time.Second, 30 * time.Second, time.Duration(math.MaxInt32) * time.Second} {
		value := adengine.InternalNativeTimeval(wait)
		converted := time.Duration(
			value.Tv_sec,
		)*time.Second + time.Duration(
			value.Tv_usec,
		)*time.Microsecond
		if converted < wait || converted-wait >= time.Microsecond || value.Tv_usec >= 1000000 ||
			adengine.InternalSecondsCeiling(wait) == 0 {
			t.Fatalf("unbounded or overflowing timeout: %s => %+v", wait, value)
		}
	}
}
