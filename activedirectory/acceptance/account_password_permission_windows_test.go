//go:build windows && (amd64 || arm64)

package acceptance

import (
	"context"
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

func TestPasswordPermissionNativeDescriptorMatchesMicrosoftReference(t *testing.T) {
	session := &adengine.InternalLdapSession{}
	for _, reference := range InternalPasswordPermissionReferenceCases(t) {
		t.Run(reference.Name, func(t *testing.T) {
			before, err := admodel.InternalDecodeDirectoryDACL(reference.Before)
			if err != nil {
				t.Fatal(err)
			}
			aces, _, err := admodel.InternalChangePasswordPermissionACEs(before, reference.Cannot)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := session.InternalEncodeDACL(reference.Before, aces)
			if err != nil {
				t.Fatal(err)
			}
			runtime.GC()
			actual, err := admodel.InternalDecodeDirectoryDACL(encoded)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := admodel.InternalDecodeDirectoryDACL(reference.After)
			if err != nil {
				t.Fatal(err)
			}
			if actual.InternalRevision != 4 ||
				len(actual.InternalAces) != len(expected.InternalAces) ||
				!admodel.InternalDirectoryACEsRetained(expected.InternalAces, actual.InternalAces) {
				t.Fatal("native descriptor differs from local Microsoft reference")
			}
			if actual.InternalControl&0x1500 != before.InternalControl&0x1500 {
				t.Fatal("native builder changed DACL inheritance control")
			}
		})
	}
}

func TestPasswordPermissionNativeReadKeepsExtraPropertiesUnderDACLControl(t *testing.T) {
	session := &adengine.InternalLdapSession{
		InternalHandle:  new(ldap.LDAP),
		InternalTimeout: time.Second,
	}
	session.InternalApi.InternalSetOption = func(*ldap.LDAP, int32, unsafe.Pointer) uint32 { return 0 }
	session.InternalApi.InternalUnbind = func(*ldap.LDAP) uint32 { return 0 }
	extra := []string{"description", "customBinary"}
	want := []string{
		"description",
		"customBinary",
		"distinguishedName",
		"objectGUID",
		"uSNChanged",
		"nTSecurityDescriptor",
		"sdRightsEffective",
		"instanceType",
		"isDeleted",
	}
	calls := 0
	session.InternalApi.InternalSearch = func(_ *ldap.LDAP, dn *string, scope uint32, filter string, attributes **uint16, only uint32, server, client **ldap.LDAPControlW, _, _ uint32, _ *uint32) uint32 {
		calls++
		runtime.GC()
		pointers := unsafe.Slice(attributes, len(want)+1)
		if pointers[len(want)] != nil {
			t.Fatal("attribute selection not terminated")
		}
		for i, name := range want {
			actual, err := adengine.InternalCopyLDAPText(pointers[i])
			if err != nil || actual != name {
				t.Fatal("wrong native selection", i, actual, err)
			}
		}
		controls := unsafe.Slice(server, 2)
		oid, err := adengine.InternalCopyLDAPText(controls[0].Ldctl_oid)
		value := controls[0].Ldctl_value
		if err != nil || oid != admodel.InternalDirectorySDFlagsControl || controls[1] != nil ||
			controls[0].Ldctl_iscritical != 1 ||
			!slices.Equal(
				unsafe.Slice((*byte)(unsafe.Pointer(value.Bv_val)), int(value.Bv_len)),
				[]byte{0x30, 3, 2, 1, 4},
			) ||
			scope != ldap.LDAP_SCOPE_BASE ||
			filter != "(objectClass=*)" ||
			only != 0 ||
			client != nil ||
			*dn != "CN=account,DC=example" {
			t.Fatal("descriptor read escaped critical DACL scope")
		}
		return 81
	}
	_, err := session.InternalReadDirectoryDACL(
		context.Background(),
		"CN=account,DC=example",
		extra,
	)
	var native *admodel.LDAPError
	if !errors.As(err, &native) || native.Code != 81 || calls != 1 ||
		!slices.Equal(extra, []string{"description", "customBinary"}) {
		t.Fatal(err, calls, extra)
	}
}
