//go:build windows && (amd64 || arm64)

package engine

import (
	"context"
	"encoding/asn1"
	"runtime"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func (s *InternalLdapSession) InternalObjectSyncPasswordPolicy(
	ctx context.Context,
	rodcDN, accountDN string,
) (map[string][][]byte, error) {
	// DER is a valid BER encoding of DNInputRequestValue (SEQUENCE/OCTET STRING).
	value, err := asn1.Marshal(struct{ InputDN []byte }{[]byte(accountDN)})
	if err != nil {
		return nil, err
	}
	control := ldap.LDAPControlW{
		Ldctl_oid:        win32.UTF16Ptr(admodel.InternalObjectSyncDNInputOID),
		Ldctl_iscritical: 1,
		Ldctl_value: ldap.LDAP_BERVAL{
			Bv_len: uint32(len(value)),
			Bv_val: foundation.PSTR(unsafe.Pointer(unsafe.SliceData(value))),
		},
	}
	attrs, err := s.InternalBaseObjectReadControls(
		ctx,
		rodcDN,
		[]string{"msDS-IsUserCachableAtRodc"},
		[]*ldap.LDAPControlW{&control, nil},
		s.InternalReadMessage,
	)
	runtime.KeepAlive(value)
	runtime.KeepAlive(control)
	return attrs, err
}
