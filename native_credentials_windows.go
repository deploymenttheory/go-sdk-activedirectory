//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"runtime"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/system/rpc"
)

func bindIdentity(api ldapAPI, handle *ldap.LDAP, credentials *Credentials, method uint32) uint32 {
	if credentials == nil {
		return api.bind(handle, nil, nil, method)
	}
	user := credentialUTF16([]byte(credentials.Username))
	domain := credentialUTF16([]byte(credentials.Domain))
	password := credentialUTF16(credentials.Password)
	auth := rpc.SEC_WINNT_AUTH_IDENTITY_W{
		User: &user[0], UserLength: uint32(len(user) - 1),
		Password: &password[0], PasswordLength: uint32(len(password) - 1),
		Flags: rpc.SEC_WINNT_AUTH_IDENTITY_UNICODE,
	}
	if credentials.Domain != "" {
		auth.Domain, auth.DomainLength = &domain[0], uint32(len(domain)-1)
	}
	// Pin every pointee for the synchronous native call and the subsequent wipe.
	// No identity storage is passed to a native free routine or retained by Client.
	var pin runtime.Pinner
	pin.Pin(&auth)
	pin.Pin(&user[0])
	pin.Pin(&domain[0])
	pin.Pin(&password[0])
	defer pin.Unpin()
	defer func() {
		api.zeroIdentity(unsafe.Pointer(&auth))
		clear(password)
		clear(user)
		clear(domain)
		auth = rpc.SEC_WINNT_AUTH_IDENTITY_W{}
		runtime.KeepAlive(password)
		runtime.KeepAlive(user)
		runtime.KeepAlive(domain)
	}()
	return api.bind(handle, nil, foundation.PWSTR(unsafe.Pointer(&auth)), method)
}

// credentialUTF16 avoids an intermediate immutable Go string for the password.
// Inputs have already passed UTF-8, NUL, and native length validation.
func credentialUTF16(value []byte) []uint16 {
	encoded := make([]uint16, 0, int(utf16Units(value))+1)
	for len(value) != 0 {
		r, size := utf8.DecodeRune(value)
		if r <= 0xffff {
			encoded = append(encoded, uint16(r))
		} else {
			high, low := utf16.EncodeRune(r)
			encoded = append(encoded, uint16(high), uint16(low))
		}
		value = value[size:]
	}
	return append(encoded, 0)
}
