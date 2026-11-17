//go:build windows && (amd64 || arm64)

package acceptance

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
	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
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
	copy(objectACE[28:], InternalOuTestACE(1, 0, 0)[8:])
	allow := InternalOuTestACE(0, 0x10, 0x20000)
	raw := InternalOuTestDescriptor(objectACE, allow)
	session := &adengine.InternalLdapSession{}
	protected, changed, err := session.InternalEditOUDACL(
		raw,
		admodel.InternalOuObjectProtectionMask,
		true,
	)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	runtime.GC()
	acl, err := admodel.InternalDecodeOUDACL(protected)
	if err != nil {
		t.Fatal(err)
	}
	if acl.InternalControl&0x1500 != 0x1400 || len(acl.InternalAces) != 3 ||
		!slices.Equal(acl.InternalAces[1], objectACE) ||
		!slices.Equal(acl.InternalAces[2], allow) {
		t.Fatalf("native descriptor changed preserved bytes: %+v", acl)
	}
	unprotected, changed, err := session.InternalEditOUDACL(
		protected,
		admodel.InternalOuObjectProtectionMask,
		false,
	)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	actual, err := admodel.InternalDecodeOUDACL(unprotected)
	if err != nil || len(actual.InternalAces) != 2 ||
		!slices.Equal(actual.InternalAces[0], objectACE) ||
		!slices.Equal(actual.InternalAces[1], allow) {
		t.Fatal("unprotect lost opaque ACE", actual, err)
	}
	if !slices.Equal(raw, InternalOuTestDescriptor(objectACE, allow)) {
		t.Fatal("original descriptor changed")
	}
}

func TestOUNativeReadUsesCriticalDACLOnlyControl(t *testing.T) {
	closes, calls := 0, 0
	session := &adengine.InternalLdapSession{
		InternalHandle:  new(ldap.LDAP),
		InternalTimeout: time.Second,
	}
	session.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	session.InternalApi.InternalUnbind = func(*ldap.LDAP) uint32 { closes++; return 0 }
	session.InternalApi.InternalSearch = func(_ *ldap.LDAP, dn *string, scope uint32, filter string, attrs **uint16, only uint32, server, client **ldap.LDAPControlW, _, _ uint32, _ *uint32) uint32 {
		calls++
		runtime.GC()
		controls := unsafe.Slice(server, 2)
		oid, err := adengine.InternalCopyLDAPText(controls[0].Ldctl_oid)
		value := controls[0].Ldctl_value
		if *dn != "OU=test,DC=example" || scope != ldap.LDAP_SCOPE_BASE ||
			filter != "(objectClass=*)" ||
			only != 0 ||
			attrs == nil ||
			client != nil ||
			controls[1] != nil ||
			err != nil ||
			oid != admodel.InternalOuSDFlagsControl ||
			controls[0].Ldctl_iscritical != 1 ||
			!slices.Equal(
				unsafe.Slice((*byte)(unsafe.Pointer(value.Bv_val)), int(value.Bv_len)),
				[]byte{0x30, 3, 2, 1, 4},
			) {
			t.Fatal("wrong descriptor read")
		}
		return 81
	}
	_, err := session.InternalReadOUDACL(context.Background(), "OU=test,DC=example")
	var native *admodel.LDAPError
	if !errors.As(err, &native) || native.Code != 81 || calls != 1 || closes != 1 {
		t.Fatal(err, calls, closes)
	}
}
