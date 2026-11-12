//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/deploymenttheory/go-bindings-win32/bindings/runtime/win32"
	"github.com/deploymenttheory/go-bindings-win32/bindings/win32/networking/ldap"
)

// Input arrives only through the lab runner's redirected stdin, never command
// arguments, environment variables, or a credential file. Artifacts are public
// observations; they do not contain this input object or password.
func TestExplicitCredentialsLab(t *testing.T) {
	if os.Getenv("ADSDK_EXPLICIT_LAB") != "1" {
		t.Skip("requires an isolated credential fixture and redirected input")
	}
	var input struct {
		Server, Domain, Username, UPN, OU, Marker string
		Password                                  []byte
	}
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
	defer clear(payload)
	if err != nil || len(payload) > 16384 {
		t.Fatal("invalid credential fixture input")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal("invalid credential fixture encoding")
	}
	defer clear(input.Password)
	if !strings.HasSuffix(strings.ToLower(input.Server), ".ad.sdk.test") ||
		!strings.HasPrefix(input.OU, "OU=ADSDK-Credential-") || !strings.HasSuffix(input.OU, ",DC=ad,DC=sdk,DC=test") ||
		!strings.HasPrefix(input.Marker, "ad-sdk-credential:") || input.UPN != input.Username+"@ad.sdk.test" {
		t.Fatal("credential fixture is outside the isolated lab namespace")
	}
	if len(input.Password) == 0 || len(input.Username) == utf8.RuneCountInString(input.Username) || len(input.Password) == utf8.RuneCount(input.Password) {
		t.Fatal("fixture must exercise non-ASCII account and password text")
	}
	if err := ldap.Procs.Ldap_add_sW.Find(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	base := Config{Endpoint: Endpoint{Host: input.Server}, Timeout: 5 * time.Second}
	current, err := Dial(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	// Prove the native request is valid and the caller can create the fixture
	// container. The same request must be denied on the alternate identity.
	status := credentialPermissionProbe(current, input.OU, "NativeAllowed", input.Marker)
	closeErr := current.Close()
	if status != 0 || closeErr != nil {
		t.Fatalf("current-identity permission baseline: LDAP %d, cleanup %v", status, closeErr)
	}
	rows := make([]map[string]any, 0, 2)
	for _, form := range []string{"domain-account", "upn"} {
		config := base
		credential := &Credentials{Username: input.Username, Domain: input.Domain, Password: input.Password}
		if form == "upn" {
			credential.Username, credential.Domain = input.UPN, ""
		}
		config.Credentials = credential
		client, err := Dial(ctx, config)
		if err != nil {
			t.Fatalf("explicit %s bind failed: %v", form, err)
		}
		// The temporary identity/password buffers have already been erased by
		// Dial. These reads verify that the authenticated session remains usable.
		root, readErr := client.RootDSE(ctx, RootDSEOptions{})
		session := client.session.(*ldapSession)
		for _, option := range []uint32{ldap.LDAP_OPT_SIGN, ldap.LDAP_OPT_ENCRYPT} {
			var enabled uint32
			code := session.api.getOption(session.handle, int32(option), unsafe.Pointer(&enabled))
			if code != 0 || enabled != 1 {
				readErr = errors.Join(readErr, errors.New("authenticated session lost signing/sealing"))
			}
		}
		denial := credentialPermissionProbe(client, input.OU, "NativeDenied", input.Marker)
		closeErr := client.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			t.Fatal(err)
		}
		if denial != 50 {
			t.Fatalf("alternate identity permission probe: expected LDAP 50, got %d", denial)
		}
		if root.DNSHostName == nil || !strings.EqualFold(*root.DNSHostName, input.Server) || root.DefaultNamingContext == nil {
			t.Fatal("post-bind RootDSE is incomplete or from another server")
		}
		rows = append(rows, map[string]any{"form": form, "server": *root.DNSHostName, "default_naming_context": *root.DefaultNamingContext, "permission_ldap_code": denial, "signing": true, "sealing": true})
	}
	for _, empty := range []bool{false, true} {
		password := append([]byte(nil), input.Password...)
		if empty {
			clear(password)
			password = password[:0]
		} else {
			password[0] ^= 1
		}
		config := base
		config.Credentials = &Credentials{Username: input.Username, Domain: input.Domain, Password: password}
		client, failure := Dial(ctx, config)
		clear(password)
		if client != nil {
			_ = client.Close()
			t.Fatal("invalid explicit credentials authenticated or fell back to current identity")
		}
		var native *LDAPError
		if !errors.As(failure, &native) || native.Operation != "ldap_bind_sW" || native.Code != 49 {
			t.Fatalf("invalid credentials lost bind status: %v", failure)
		}
	}
	artifact := map[string]any{"passed": true, "unicode_fixture": true, "current_identity_add_code": status, "wrong_password_code": 49, "empty_password_code": 49, "reads": rows}
	path := os.Getenv("ADSDK_CREDENTIAL_RESULT")
	if path == "" {
		t.Fatal("missing nonsecret result destination")
	}
	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

// This controlled native operation is a lab-only authorization probe, not a
// public SDK mutation API. The runner owns the OU and removes marked children.
func credentialPermissionProbe(client *Client, ou, name, marker string) uint32 {
	var pin runtime.Pinner
	defer pin.Unpin()
	mods := make([]*ldap.LDAPModW, 0, 4)
	for _, attr := range [][2]string{{"objectClass", "container"}, {"cn", name}, {"description", marker}} {
		attribute, value := win32.UTF16Ptr(attr[0]), win32.UTF16Ptr(attr[1])
		values := []*uint16{value, nil}
		mod := &ldap.LDAPModW{Mod_type: attribute}
		*(***uint16)(unsafe.Pointer(&mod.Mod_vals)) = &values[0]
		pin.Pin(attribute)
		pin.Pin(value)
		pin.Pin(&values[0])
		pin.Pin(mod)
		mods = append(mods, mod)
	}
	mods = append(mods, nil)
	pin.Pin(&mods[0])
	session := client.session.(*ldapSession)
	status := ldap.Ldap_add_sW(session.handle, "CN="+name+","+ou, &mods[0])
	runtime.KeepAlive(mods)
	return status
}
