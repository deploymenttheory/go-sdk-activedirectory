package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// A password must never reach a log, a JSON document or a formatted string.
// Every formatting path on the request is asserted, because adding one that
// prints fields by default would silently leak the credential.
func TestInstallRequestRedactsEverywhere(t *testing.T) {
	secret := "SuperSecretPassw0rd!"
	request := InstallLocalServiceAccountRequest{AccountPassword: []byte(secret)}

	for name, rendered := range map[string]string{
		"%v":       fmt.Sprintf("%v", request),
		"%s":       fmt.Sprintf("%s", request),
		"%#v":      fmt.Sprintf("%#v", request),
		"%+v":      fmt.Sprintf("%+v", request),
		"String()": request.String(),
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("%s leaked the password: %s", name, rendered)
		}
		if !strings.Contains(strings.ToLower(rendered), "redacted") {
			t.Fatalf("%s did not mark itself redacted: %s", name, rendered)
		}
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("JSON leaked the password: %s", encoded)
	}
	text, err := request.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), secret) {
		t.Fatalf("text leaked the password: %s", text)
	}
	// Marshalling a struct that merely embeds the request must not leak either.
	wrapper, err := json.Marshal(struct {
		Request InstallLocalServiceAccountRequest
	}{request})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wrapper), secret) {
		t.Fatalf("embedded JSON leaked the password: %s", wrapper)
	}
}

func TestLocalServiceAccountName(t *testing.T) {
	// The directory stores a managed account's sAMAccountName with a trailing
	// '$'; the native APIs take the name without it.
	for sam, want := range map[string]string{
		"svc$":            "svc",
		"svc":             "svc",
		"fifteenchars15$": "fifteenchars15",
	} {
		got, err := localServiceAccountName(sam)
		if err != nil || got != want {
			t.Fatalf("%q: got %q err=%v, want %q", sam, got, err, want)
		}
	}
	// Separators and oversized names are rejected rather than truncated, so a
	// name can never be reinterpreted as a qualified or UPN-style identity.
	for _, sam := range []string{
		"$", "", `dom\svc$`, "svc@dom$", "a/b$", "sixteencharacter$", "sixteencharacters",
		"svc\x00$",
	} {
		if got, err := localServiceAccountName(sam); !errors.Is(err, ErrInvalidServiceAccountInstall) {
			t.Fatalf("%q: expected rejection, got %q err=%v", sam, got, err)
		}
	}
}

func TestLocalServiceAccountNativeError(t *testing.T) {
	// The NTSTATUS bit pattern survives and is never reformatted as a Win32
	// error, and the message carries no account or password text.
	err := &LocalServiceAccountNativeError{Operation: "NetAddServiceAccount", Status: 0xC0000022}
	if !strings.Contains(err.Error(), "0xC0000022") {
		t.Fatalf("status was not preserved: %s", err.Error())
	}
	// STATUS_ACCESS_DENIED and STATUS_PRIVILEGE_NOT_HELD both mean the caller
	// lacks permission, so both must match the permission sentinel.
	for _, status := range []uint32{0xc0000022, 0xc0000061} {
		candidate := &LocalServiceAccountNativeError{Operation: "op", Status: status}
		if !errors.Is(candidate, ErrServiceAccountLocalPermission) {
			t.Fatalf("status 0x%08X must be a permission error", status)
		}
	}
	// An unrelated status must not be reported as a permission problem.
	other := &LocalServiceAccountNativeError{Operation: "op", Status: 0xC000000D}
	if errors.Is(other, ErrServiceAccountLocalPermission) {
		t.Fatal("an unrelated status must not match the permission sentinel")
	}
}

func TestLocalServiceAccountAttemptError(t *testing.T) {
	status := func(v uint32) *uint32 { return &v }
	// An uncertain attempt must say so: the caller has to reconcile before
	// trying again, and nothing may be replayed automatically.
	err := localServiceAccountAttemptError(LocalServiceAccountAttempt{State: ObjectWriteUncertain, Operation: "op"})
	if !errors.Is(err, ErrServiceAccountLocalUncertain) {
		t.Fatalf("uncertain attempt: %v", err)
	}
	// A nonzero NTSTATUS surfaces as a native error.
	err = localServiceAccountAttemptError(LocalServiceAccountAttempt{State: ObjectWriteAccepted, Operation: "op", Status: status(0xC0000022)})
	var native *LocalServiceAccountNativeError
	if !errors.As(err, &native) || native.Status != 0xC0000022 {
		t.Fatalf("native status was not surfaced: %v", err)
	}
	// A missing status, or one that was never attempted, is an invalid result
	// rather than a silent success.
	for name, attempt := range map[string]LocalServiceAccountAttempt{
		"no status":     {State: ObjectWriteAccepted, Operation: "op"},
		"not attempted": {State: ObjectWriteNotAttempted, Operation: "op", Status: status(0)},
	} {
		if err := localServiceAccountAttemptError(attempt); !errors.Is(err, ErrInvalidResult) {
			t.Fatalf("%s: expected ErrInvalidResult, got %v", name, err)
		}
	}
	// Success is only success when the status is zero and the write was accepted.
	if err := localServiceAccountAttemptError(LocalServiceAccountAttempt{State: ObjectWriteAccepted, Operation: "op", Status: status(0)}); err != nil {
		t.Fatalf("accepted zero status must succeed: %v", err)
	}
	if err := localServiceAccountAttemptError(LocalServiceAccountAttempt{State: ObjectWriteRejected, Operation: "op", Status: status(0)}); !errors.Is(err, ErrInvalidResult) {
		t.Fatal("a rejected write with a zero status is not a success")
	}
}

func TestLockLocalServiceAccountHonoursCancellation(t *testing.T) {
	// The gate serialises this process's local workflows. A caller whose
	// context is already cancelled must not wait on it.
	if err := lockLocalServiceAccount(t.Context()); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := lockLocalServiceAccount(cancelled); err == nil {
		<-localServiceAccountGate
		t.Fatal("a cancelled context must not acquire the gate")
	}
	<-localServiceAccountGate
	// The gate is reusable once released.
	if err := lockLocalServiceAccount(t.Context()); err != nil {
		t.Fatalf("gate was not released: %v", err)
	}
	<-localServiceAccountGate
}

// localTestBackend stands in for the native host so the workflow can be driven
// without touching the executing machine.
type localTestBackend struct {
	hostValue   LocalServiceAccountHost
	hostErr     error
	presence    []*bool
	presenceErr error
	attempts    []LocalServiceAccountAttempt
	installed_  []string
	passwords   [][]byte
	flags       []uint32
}

func (b *localTestBackend) host(context.Context) (LocalServiceAccountHost, error) {
	return b.hostValue, b.hostErr
}

// installed reports presence as a tri-state. An unknown presence stays nil:
// reading it as absent could turn an install into a silent overwrite.
func (b *localTestBackend) installed(_ context.Context, name string) (*bool, error) {
	if b.presenceErr != nil {
		return nil, b.presenceErr
	}
	if len(b.presence) == 0 {
		return nil, nil
	}
	value := b.presence[0]
	b.presence = b.presence[1:]
	return value, nil
}

func (b *localTestBackend) install(_ context.Context, name string, password []byte, flags uint32) LocalServiceAccountAttempt {
	b.installed_ = append(b.installed_, name)
	// Retain a copy: the workflow erases the caller's buffer on exit, so the
	// recorded value must not alias it.
	b.passwords = append(b.passwords, append([]byte(nil), password...))
	b.flags = append(b.flags, flags)
	return b.attempt("NetAddServiceAccount")
}

func (b *localTestBackend) uninstall(_ context.Context, name string, flags uint32) LocalServiceAccountAttempt {
	b.flags = append(b.flags, flags)
	return b.attempt("NetRemoveServiceAccount")
}

func (b *localTestBackend) attempt(operation string) LocalServiceAccountAttempt {
	if len(b.attempts) == 0 {
		zero := uint32(0)
		return LocalServiceAccountAttempt{Operation: operation, State: ObjectWriteAccepted, Status: &zero}
	}
	value := b.attempts[0]
	b.attempts = b.attempts[1:]
	return value
}

// The fake must satisfy the real backend contract, so a signature change to
// the native boundary breaks this test rather than going unnoticed.
var _ localServiceAccountBackend = (*localTestBackend)(nil)

func TestLocalBackendContractIsExercisable(t *testing.T) {
	// The workflow depends on the backend reporting presence as a tri-state:
	// true, false, or unknown. An unknown presence must not be read as absent,
	// because installing over an unknown state could be a silent overwrite.
	yes, no := true, false
	backend := &localTestBackend{presence: []*bool{&yes, &no, nil}}
	first, err := backend.installed(t.Context(), "svc")
	if err != nil || first == nil || !*first {
		t.Fatalf("first presence: %+v err=%v", first, err)
	}
	second, err := backend.installed(t.Context(), "svc")
	if err != nil || second == nil || *second {
		t.Fatalf("second presence: %+v err=%v", second, err)
	}
	third, err := backend.installed(t.Context(), "svc")
	if err != nil || third != nil {
		t.Fatalf("unknown presence must stay nil: %+v err=%v", third, err)
	}
}

func TestUninstallRequestForceRemoveLocalIsExplicit(t *testing.T) {
	// ForceRemoveLocal is not a general retry: it exists for one documented
	// offline-removal reply and must default off.
	var request UninstallLocalServiceAccountRequest
	if request.ForceRemoveLocal {
		t.Fatal("ForceRemoveLocal must default to false")
	}
	if request.Preview {
		t.Fatal("Preview must default to false")
	}
}

func TestInstallRequestPreviewDefaultsOff(t *testing.T) {
	// A zero request must not preview-only, and must not carry a password.
	var request InstallLocalServiceAccountRequest
	if request.Preview || request.Force || request.AccountPassword != nil || request.PasswordPrompt != nil {
		t.Fatalf("zero request is not inert: %+v", struct {
			Preview, Force bool
			HasPassword    bool
			HasPrompt      bool
		}{request.Preview, request.Force, request.AccountPassword != nil, request.PasswordPrompt != nil})
	}
}
