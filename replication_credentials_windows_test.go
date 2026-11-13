//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/foundation"
	nativead "github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/activedirectory"
)

func TestReplicationCredentialsUseAndEraseMutableUnicodeBuffers(t *testing.T) {
	for _, mode := range []string{"success", "maker-failure", "null-owner", "upn"} {
		t.Run(mode, func(t *testing.T) {
			credentials := &Credentials{Username: "synthetic-üser-\U0001f512", Domain: "synthetic-dömain", Password: []byte("synthetic-密碼-\U0001f680")}
			if mode == "upn" {
				credentials.Username += "@synthetic.invalid"
				credentials.Domain = ""
			}
			original := slices.Clone(credentials.Password)
			defer clear(original)
			defer clear(credentials.Password)
			owner := new(byte)
			var borrowed [][]uint16
			calls := 0
			got, err := makeReplicationCredentialsWithAPI(credentials, func(user, domain, password foundation.PWSTR, out *unsafe.Pointer) uint32 {
				calls++
				for _, field := range []struct {
					pointer *uint16
					want    []uint16
				}{{user, credentialUTF16([]byte(credentials.Username))}, {domain, credentialUTF16([]byte(credentials.Domain))}, {password, credentialUTF16(credentials.Password)}} {
					if field.pointer == nil {
						if credentials.Domain != "" || len(field.want) != 1 {
							t.Fatal("unexpected NULL credential input")
						}
						continue
					}
					buffer := unsafe.Slice(field.pointer, len(field.want))
					if !slices.Equal(buffer, field.want) {
						t.Fatal("Unicode credential units changed")
					}
					borrowed = append(borrowed, buffer)
					clear(field.want)
				}
				if mode != "null-owner" {
					*out = unsafe.Pointer(owner)
				}
				if mode == "maker-failure" {
					return 87
				}
				return 0
			})
			if calls != 1 {
				t.Fatalf("native maker calls=%d err=%v", calls, err)
			}
			if mode == "null-owner" {
				if got != nil || !errors.Is(err, ErrInvalidNativeResult) {
					t.Fatalf("NULL success=%p %v", got, err)
				}
			} else {
				if got != unsafe.Pointer(owner) {
					t.Fatal("native owner was lost")
				}
				if mode == "maker-failure" {
					var status *NativeStatusError
					if !errors.As(err, &status) || status.Code != 87 {
						t.Fatalf("maker status lost: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			for _, buffer := range borrowed {
				for _, unit := range buffer {
					if unit != 0 {
						t.Fatal("native UTF-16 credential buffer was not erased")
					}
				}
			}
			if !bytes.Equal(credentials.Password, original) {
				t.Fatal("caller-owned password was modified")
			}
		})
	}
}

func TestReplicationNativeCredentialMakeFree(t *testing.T) {
	credentials := &Credentials{Username: "sdk-synthetic-üser@synthetic.invalid", Password: []byte("synthetic-密碼-\U0001f680")}
	defer clear(credentials.Password)
	owner, err := makeReplicationCredentials(credentials)
	if owner != nil {
		defer nativead.DsFreePasswordCredentials(owner)
	}
	if err != nil || owner == nil {
		t.Fatalf("host-only credential creation: owner=%t err=%v", owner != nil, err)
	}
}

func TestReplicationCredentialsValidateBeforeNativeAllocation(t *testing.T) {
	called := false
	makeCredential := func(foundation.PWSTR, foundation.PWSTR, foundation.PWSTR, *unsafe.Pointer) uint32 {
		called = true
		return 0
	}
	if owner, err := makeReplicationCredentialsWithAPI(nil, makeCredential); owner != nil || err != nil || called {
		t.Fatalf("current identity unexpectedly allocated: %v", err)
	}
	for _, credentials := range []*Credentials{{Username: "unqualified", Password: []byte("synthetic")}, {Username: "user", Domain: "TEST", Password: []byte{0xff}}, {Username: "user", Domain: "TEST", Password: []byte{'x', 0, 'y'}}} {
		if _, err := makeReplicationCredentialsWithAPI(credentials, makeCredential); err == nil || called {
			t.Fatal("invalid explicit credentials reached native allocation")
		}
	}
}
