//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func TestNativeDialOwnershipAndSecurityOptions(t *testing.T) {
	for _, failure := range []string{"none", "missing-export", "init", "option", "connect", "bind", "bind-and-close"} {
		t.Run(failure, func(t *testing.T) {
			api := systemLDAPAPI()
			init, unbind, set := api.init, api.unbind, api.setOption
			allocations, frees, binds := 0, 0, 0
			options := make(map[int32]uint32)
			api.init = func(host string, port uint32) *ldap.LDAP {
				if failure == "init" {
					return nil
				}
				handle := init(host, port)
				if handle != nil {
					allocations++
				}
				return handle
			}
			api.lastError = func() uint32 { return 90 }
			api.unbind = func(handle *ldap.LDAP) uint32 {
				frees++
				status := unbind(handle)
				if failure == "bind-and-close" {
					return 80
				}
				return status
			}
			api.setOption = func(handle *ldap.LDAP, option int32, value unsafe.Pointer) uint32 {
				options[option] = *(*uint32)(value)
				if failure == "option" && option == int32(ldap.LDAP_OPT_ENCRYPT) {
					return 53
				}
				return set(handle, option, value)
			}
			api.connect = func(_ *ldap.LDAP, timeout *ldap.LDAP_TIMEVAL) uint32 {
				if timeout.Tv_sec != 0 || timeout.Tv_usec != 250000 {
					t.Errorf("connect timeout: %+v", timeout)
				}
				if failure == "connect" {
					return 81
				}
				return 0
			}
			api.bind = func(_ *ldap.LDAP, dn, credential *string, method uint32) uint32 {
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
				api.find = func(*win32.Proc) error { return errors.New("injected missing export") }
			}
			config := Config{Endpoint: Endpoint{Host: "dc1.ad.sdk.test", Port: 389}, Timeout: 250 * time.Millisecond}
			session, err := dialWithAPI(context.Background(), config, api)
			if failure == "none" {
				if err != nil {
					t.Fatal(err)
				}
				if err := session.close(); err != nil {
					t.Fatal(err)
				}
				if err := session.close(); err != nil {
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
				if failure == "missing-export" && !errors.Is(err, ErrUnsupported) {
					t.Fatalf("missing export: %v", err)
				}
				if failure == "bind-and-close" && (!hasLDAPCode(err, 49) || !hasLDAPCode(err, 80)) {
					t.Fatalf("lost operation or cleanup status: %v", err)
				}
			}
			if allocations != frees {
				t.Fatalf("allocated %d, freed %d", allocations, frees)
			}
		})
	}
}

func hasLDAPCode(err error, code uint32) bool {
	if err == nil {
		return false
	}
	if native, ok := err.(*LDAPError); ok {
		return native.Code == code
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if hasLDAPCode(child, code) {
				return true
			}
		}
	}
	return hasLDAPCode(errors.Unwrap(err), code)
}

func TestNativeResultFailureFreesMessageBeforeAbandon(t *testing.T) {
	message := new(ldap.LDAPMessage)
	var order []string
	session := &ldapSession{handle: new(ldap.LDAP), api: ldapAPI{
		result: func(_ *ldap.LDAP, _ uint32, all uint32, _ *ldap.LDAP_TIMEVAL, out **ldap.LDAPMessage) uint32 {
			order = append(order, "result")
			if all != ldap.LDAP_MSG_ALL {
				t.Error("must collect complete chain")
			}
			*out = message
			return math.MaxUint32
		},
		getOption: func(_ *ldap.LDAP, _ int32, out unsafe.Pointer) uint32 { *(*uint32)(out) = 81; return 0 },
		messageFree: func(got *ldap.LDAPMessage) uint32 {
			if got != message {
				t.Error("wrong message")
			}
			order = append(order, "free")
			return 0
		},
		abandon: func(_ *ldap.LDAP, id uint32) uint32 {
			if id != 7 {
				t.Error("wrong ID")
			}
			order = append(order, "abandon")
			return 0
		},
	}}
	_, err := session.waitRootDSE(context.Background(), 7)
	if !hasLDAPCode(err, 81) || len(order) != 3 || order[0] != "result" || order[1] != "free" || order[2] != "abandon" {
		t.Fatalf("failure=%v order=%v", err, order)
	}
}

func TestNativeCanceledReadRetiresSessionWhenAbandonFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	frees := 0
	session := &ldapSession{handle: new(ldap.LDAP), api: ldapAPI{
		abandon: func(*ldap.LDAP, uint32) uint32 { return 81 },
		unbind:  func(*ldap.LDAP) uint32 { frees++; return 80 },
	}}
	_, err := session.waitRootDSE(ctx, 7)
	if !errors.Is(err, context.Canceled) || !hasLDAPCode(err, 81) || !hasLDAPCode(err, 80) || frees != 1 || session.handle != nil {
		t.Fatalf("failure=%v frees=%d handle=%p", err, frees, session.handle)
	}
	_ = session.close()
	if frees != 1 {
		t.Fatal("double unbind")
	}
}

func TestNativeTimeoutRounding(t *testing.T) {
	for _, wait := range []time.Duration{time.Nanosecond, time.Microsecond, 999999999 * time.Nanosecond, time.Second, 30 * time.Second, time.Duration(math.MaxInt32) * time.Second} {
		value := nativeTimeval(wait)
		converted := time.Duration(value.Tv_sec)*time.Second + time.Duration(value.Tv_usec)*time.Microsecond
		if converted < wait || converted-wait >= time.Microsecond || value.Tv_usec >= 1000000 || secondsCeiling(wait) == 0 {
			t.Fatalf("unbounded or overflowing timeout: %s => %+v", wait, value)
		}
	}
}
