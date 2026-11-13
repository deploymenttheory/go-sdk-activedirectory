//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"slices"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func TestOUNativeDescriptorRetainsOpaqueAndInheritedACEs(t *testing.T) {
	objectACE := make([]byte, 40)
	objectACE[0] = 6
	binary.LittleEndian.PutUint16(objectACE[2:4], 40)
	binary.LittleEndian.PutUint32(objectACE[4:8], 0x20)
	binary.LittleEndian.PutUint32(objectACE[8:12], 1)
	for i := 12; i < 28; i++ {
		objectACE[i] = byte(i)
	}
	copy(objectACE[28:], ouTestACE(1, 0, 0)[8:])
	allow := ouTestACE(0, 0x10, 0x20000)
	raw := ouTestDescriptor(objectACE, allow)
	session := &ldapSession{}
	protected, changed, err := session.editOUDACL(raw, ouObjectProtectionMask, true)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	runtime.GC()
	acl, err := decodeOUDACL(protected)
	if err != nil {
		t.Fatal(err)
	}
	if acl.control&0x1500 != 0x1400 || len(acl.aces) != 3 || !slices.Equal(acl.aces[1], objectACE) || !slices.Equal(acl.aces[2], allow) {
		t.Fatalf("native descriptor changed preserved bytes: %+v", acl)
	}
	unprotected, changed, err := session.editOUDACL(protected, ouObjectProtectionMask, false)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	actual, err := decodeOUDACL(unprotected)
	if err != nil || len(actual.aces) != 2 || !slices.Equal(actual.aces[0], objectACE) || !slices.Equal(actual.aces[1], allow) {
		t.Fatal("unprotect lost opaque ACE", actual, err)
	}
	if !slices.Equal(raw, ouTestDescriptor(objectACE, allow)) {
		t.Fatal("original descriptor changed")
	}
}

func TestOUNativeReadUsesCriticalDACLOnlyControl(t *testing.T) {
	closes, calls := 0, 0
	session := &ldapSession{handle: new(ldap.LDAP), timeout: time.Second}
	session.api.setOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	session.api.unbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
	session.api.search = func(_ *ldap.LDAP, dn *string, scope uint32, filter string, attrs **uint16, only uint32, server, client **ldap.LDAPControlW, _, _ uint32, _ *uint32) uint32 {
		calls++
		runtime.GC()
		controls := unsafe.Slice(server, 2)
		oid, err := copyLDAPText(controls[0].Ldctl_oid)
		value := controls[0].Ldctl_value
		if *dn != "OU=test,DC=example" || scope != ldap.LDAP_SCOPE_BASE || filter != "(objectClass=*)" || only != 0 || attrs == nil || client != nil || controls[1] != nil || err != nil || oid != ouSDFlagsControl || controls[0].Ldctl_iscritical != 1 || !slices.Equal(unsafe.Slice((*byte)(unsafe.Pointer(value.Bv_val)), int(value.Bv_len)), []byte{0x30, 3, 2, 1, 4}) {
			t.Fatal("wrong descriptor read")
		}
		return 81
	}
	_, err := session.readOUDACL(context.Background(), "OU=test,DC=example")
	var native *LDAPError
	if !errors.As(err, &native) || native.Code != 81 || calls != 1 || closes != 1 {
		t.Fatal(err, calls, closes)
	}
}
