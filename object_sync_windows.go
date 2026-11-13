//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"encoding/asn1"
	"runtime"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

func (s *ldapSession) objectSyncPasswordPolicy(ctx context.Context, rodcDN, accountDN string) (map[string][][]byte, error) {
	// DER is a valid BER encoding of DNInputRequestValue (SEQUENCE/OCTET STRING).
	value, err := asn1.Marshal(struct{ InputDN []byte }{[]byte(accountDN)})
	if err != nil {
		return nil, err
	}
	control := ldap.LDAPControlW{
		Ldctl_oid: win32.UTF16Ptr(objectSyncDNInputOID), Ldctl_iscritical: 1,
		Ldctl_value: ldap.LDAP_BERVAL{Bv_len: uint32(len(value)), Bv_val: foundation.PSTR(unsafe.Pointer(unsafe.SliceData(value)))},
	}
	attrs, err := s.baseObjectReadControls(ctx, rodcDN, []string{"msDS-IsUserCachableAtRodc"}, []*ldap.LDAPControlW{&control, nil}, s.readMessage)
	runtime.KeepAlive(value)
	runtime.KeepAlive(control)
	return attrs, err
}
