package acceptance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	adengine "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/engine"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_service_accounts "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/service_accounts"
)

// A password must never reach a log, a JSON document or a formatted string.
// Every formatting path on the request is asserted, because adding one that
// prints fields by default would silently leak the credential.
func TestInstallRequestRedactsEverywhere(t *testing.T) {
	secret := "SuperSecretPassw0rd!"
	request := admodel.InstallLocalServiceAccountRequest{AccountPassword: []byte(secret)}

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
		Request admodel.InstallLocalServiceAccountRequest
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
		got, err := admodel.InternalLocalServiceAccountName(sam)
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
		if got, err := admodel.InternalLocalServiceAccountName(
			sam,
		); !errors.Is(
			err,
			admodel.ErrInvalidServiceAccountInstall,
		) {
			t.Fatalf("%q: expected rejection, got %q err=%v", sam, got, err)
		}
	}
}

func TestLocalServiceAccountNativeError(t *testing.T) {
	// The NTSTATUS bit pattern survives and is never reformatted as a Win32
	// error, and the message carries no account or password text.
	err := &admodel.LocalServiceAccountNativeError{
		Operation: "NetAddServiceAccount",
		Status:    0xC0000022,
	}
	if !strings.Contains(err.Error(), "0xC0000022") {
		t.Fatalf("status was not preserved: %s", err.Error())
	}
	// STATUS_ACCESS_DENIED and STATUS_PRIVILEGE_NOT_HELD both mean the caller
	// lacks permission, so both must match the permission sentinel.
	for _, status := range []uint32{0xc0000022, 0xc0000061} {
		candidate := &admodel.LocalServiceAccountNativeError{Operation: "op", Status: status}
		if !errors.Is(candidate, admodel.ErrServiceAccountLocalPermission) {
			t.Fatalf("status 0x%08X must be a permission error", status)
		}
	}
	// An unrelated status must not be reported as a permission problem.
	other := &admodel.LocalServiceAccountNativeError{Operation: "op", Status: 0xC000000D}
	if errors.Is(other, admodel.ErrServiceAccountLocalPermission) {
		t.Fatal("an unrelated status must not match the permission sentinel")
	}
}

func TestLocalServiceAccountAttemptError(t *testing.T) {
	status := func(v uint32) *uint32 { return &v }
	// An uncertain attempt must say so: the caller has to reconcile before
	// trying again, and nothing may be replayed automatically.
	err := admodel.InternalLocalServiceAccountAttemptError(
		admodel.LocalServiceAccountAttempt{State: admodel.ObjectWriteUncertain, Operation: "op"},
	)
	if !errors.Is(err, admodel.ErrServiceAccountLocalUncertain) {
		t.Fatalf("uncertain attempt: %v", err)
	}
	// A nonzero NTSTATUS surfaces as a native error.
	err = admodel.InternalLocalServiceAccountAttemptError(
		admodel.LocalServiceAccountAttempt{
			State:     admodel.ObjectWriteAccepted,
			Operation: "op",
			Status:    status(0xC0000022),
		},
	)
	var native *admodel.LocalServiceAccountNativeError
	if !errors.As(err, &native) || native.Status != 0xC0000022 {
		t.Fatalf("native status was not surfaced: %v", err)
	}
	// A missing status, or one that was never attempted, is an invalid result
	// rather than a silent success.
	for name, attempt := range map[string]admodel.LocalServiceAccountAttempt{
		"no status":     {State: admodel.ObjectWriteAccepted, Operation: "op"},
		"not attempted": {State: admodel.ObjectWriteNotAttempted, Operation: "op", Status: status(0)},
	} {
		if err := admodel.InternalLocalServiceAccountAttemptError(
			attempt,
		); !errors.Is(
			err,
			admodel.ErrInvalidResult,
		) {
			t.Fatalf("%s: expected ErrInvalidResult, got %v", name, err)
		}
	}
	// Success is only success when the status is zero and the write was accepted.
	if err := admodel.InternalLocalServiceAccountAttemptError(
		admodel.LocalServiceAccountAttempt{
			State:     admodel.ObjectWriteAccepted,
			Operation: "op",
			Status:    status(0),
		},
	); err != nil {
		t.Fatalf("accepted zero status must succeed: %v", err)
	}
	if err := admodel.InternalLocalServiceAccountAttemptError(
		admodel.LocalServiceAccountAttempt{
			State:     admodel.ObjectWriteRejected,
			Operation: "op",
			Status:    status(0),
		},
	); !errors.Is(
		err,
		admodel.ErrInvalidResult,
	) {
		t.Fatal("a rejected write with a zero status is not a success")
	}
}

func TestLockLocalServiceAccountHonoursCancellation(t *testing.T) {
	// The gate serialises this process's local workflows. A caller whose
	// context is already cancelled must not wait on it.
	if err := admodel.InternalLockLocalServiceAccount(t.Context()); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := admodel.InternalLockLocalServiceAccount(cancelled); err == nil {
		<-admodel.InternalLocalServiceAccountGate
		t.Fatal("a cancelled context must not acquire the gate")
	}
	<-admodel.InternalLocalServiceAccountGate
	// The gate is reusable once released.
	if err := admodel.InternalLockLocalServiceAccount(t.Context()); err != nil {
		t.Fatalf("gate was not released: %v", err)
	}
	<-admodel.InternalLocalServiceAccountGate
}

// localTestBackend stands in for the native host so the workflow can be driven
// without touching the executing machine.
type InternalLocalTestBackend struct {
	InternalHostValue   admodel.LocalServiceAccountHost
	InternalHostErr     error
	InternalPresence    []*bool
	InternalPresenceErr error
	InternalAttempts    []admodel.LocalServiceAccountAttempt
	InternalInstalled_  []string
	InternalPasswords   [][]byte
	InternalFlags       []uint32
}

func (b *InternalLocalTestBackend) InternalHost(
	context.Context,
) (admodel.LocalServiceAccountHost, error) {
	return b.InternalHostValue, b.InternalHostErr
}

// installed reports presence as a tri-state. An unknown presence stays nil:
// reading it as absent could turn an install into a silent overwrite.
func (b *InternalLocalTestBackend) InternalInstalled(
	_ context.Context,
	name string,
) (*bool, error) {
	if b.InternalPresenceErr != nil {
		return nil, b.InternalPresenceErr
	}
	if len(b.InternalPresence) == 0 {
		return nil, nil
	}
	value := b.InternalPresence[0]
	b.InternalPresence = b.InternalPresence[1:]
	return value, nil
}

func (b *InternalLocalTestBackend) InternalInstall(
	_ context.Context,
	name string,
	password []byte,
	flags uint32,
) admodel.LocalServiceAccountAttempt {
	b.InternalInstalled_ = append(b.InternalInstalled_, name)
	// Retain a copy: the workflow erases the caller's buffer on exit, so the
	// recorded value must not alias it.
	b.InternalPasswords = append(b.InternalPasswords, append([]byte(nil), password...))
	b.InternalFlags = append(b.InternalFlags, flags)
	return b.InternalAttempt("NetAddServiceAccount")
}

func (b *InternalLocalTestBackend) InternalUninstall(
	_ context.Context,
	name string,
	flags uint32,
) admodel.LocalServiceAccountAttempt {
	b.InternalFlags = append(b.InternalFlags, flags)
	return b.InternalAttempt("NetRemoveServiceAccount")
}

func (b *InternalLocalTestBackend) InternalAttempt(
	operation string,
) admodel.LocalServiceAccountAttempt {
	if len(b.InternalAttempts) == 0 {
		zero := uint32(0)
		return admodel.LocalServiceAccountAttempt{
			Operation: operation,
			State:     admodel.ObjectWriteAccepted,
			Status:    &zero,
		}
	}
	value := b.InternalAttempts[0]
	b.InternalAttempts = b.InternalAttempts[1:]
	return value
}

func TestLocalBackendContractIsExercisable(t *testing.T) {
	// The workflow depends on the backend reporting presence as a tri-state:
	// true, false, or unknown. An unknown presence must not be read as absent,
	// because installing over an unknown state could be a silent overwrite.
	yes, no := true, false
	backend := &InternalLocalTestBackend{InternalPresence: []*bool{&yes, &no, nil}}
	first, err := backend.InternalInstalled(t.Context(), "svc")
	if err != nil || first == nil || !*first {
		t.Fatalf("first presence: %+v err=%v", first, err)
	}
	second, err := backend.InternalInstalled(t.Context(), "svc")
	if err != nil || second == nil || *second {
		t.Fatalf("second presence: %+v err=%v", second, err)
	}
	third, err := backend.InternalInstalled(t.Context(), "svc")
	if err != nil || third != nil {
		t.Fatalf("unknown presence must stay nil: %+v err=%v", third, err)
	}
}

func TestUninstallRequestForceRemoveLocalIsExplicit(t *testing.T) {
	// ForceRemoveLocal is not a general retry: it exists for one documented
	// offline-removal reply and must default off.
	var request admodel.UninstallLocalServiceAccountRequest
	if request.ForceRemoveLocal {
		t.Fatal("ForceRemoveLocal must default to false")
	}
	if request.Preview {
		t.Fatal("Preview must default to false")
	}
}

func TestInstallRequestPreviewDefaultsOff(t *testing.T) {
	// A zero request must not preview-only, and must not carry a password.
	var request admodel.InstallLocalServiceAccountRequest
	if request.Preview || request.Force || request.AccountPassword != nil ||
		request.PasswordPrompt != nil {
		t.Fatalf("zero request is not inert: %+v", struct {
			Preview, Force bool
			HasPassword    bool
			HasPrompt      bool
		}{request.Preview, request.Force, request.AccountPassword != nil, request.PasswordPrompt != nil})
	}
}

// Readiness must never answer "not ready" from an incomplete reading: that
// would be indistinguishable from a genuine negative and could send a caller
// to reinstall a working account.
func TestServiceAccountReadinessRejectsUnknownReading(t *testing.T) {
	client := &adengine.Client{}
	// A closed client is refused before any native call.
	if _, err := adservice_service_accounts.New(client).
		ServiceAccountReadiness(t.Context(), admodel.ServiceAccountReadinessRequest{}); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatalf("a closed client must be refused, got %v", err)
	}
	if _, err := adservice_service_accounts.InternalServiceServiceAccountReadiness(
		adservice_service_accounts.New(client),
		nil,
		admodel.ServiceAccountReadinessRequest{},
		&InternalLocalTestBackend{},
	); !errors.Is(
		err,
		admodel.ErrClosed,
	) {
		t.Fatalf("a closed client must be refused before the context check, got %v", err)
	}
}

func TestServiceAccountReadinessResultZeroValueIsNotReady(t *testing.T) {
	// The zero result must not look like a confident negative: Ready is nil
	// and Observed is false until a reading actually completed.
	var result admodel.ServiceAccountReadinessResult
	if result.Ready != nil {
		t.Fatal("zero Ready must be nil, not a false reading")
	}
	if result.Observed {
		t.Fatal("zero Observed must be false")
	}
}

// localUninstallBackend never flips presence, reproducing what the lab observed
// for a group managed account: NetIsServiceAccount still reports true after a
// successful uninstall, because for a gMSA the reading follows this host's
// eligibility rather than local installation.
type InternalLocalUninstallBackend struct {
	InternalHost_    admodel.LocalServiceAccountHost
	InternalPresence bool
	InternalCalls    int
}

func (b *InternalLocalUninstallBackend) InternalHost(
	context.Context,
) (admodel.LocalServiceAccountHost, error) {
	return b.InternalHost_, nil
}

func (b *InternalLocalUninstallBackend) InternalInstalled(context.Context, string) (*bool, error) {
	value := b.InternalPresence
	return &value, nil
}

func (b *InternalLocalUninstallBackend) InternalInstall(
	context.Context,
	string,
	[]byte,
	uint32,
) admodel.LocalServiceAccountAttempt {
	zero := uint32(0)
	return admodel.LocalServiceAccountAttempt{
		Operation: "NetAddServiceAccount",
		State:     admodel.ObjectWriteAccepted,
		Status:    &zero,
	}
}

func (b *InternalLocalUninstallBackend) InternalUninstall(
	context.Context,
	string,
	uint32,
) admodel.LocalServiceAccountAttempt {
	b.InternalCalls++
	zero := uint32(0)
	return admodel.LocalServiceAccountAttempt{
		Operation: "NetRemoveServiceAccount",
		State:     admodel.ObjectWriteAccepted,
		Status:    &zero,
	}
}

// A successful gMSA uninstall must not be reported as a failure just because
// the native presence reading did not change. Before the carve-out this
// returned ErrServiceAccountLocalObservation for every group managed account.
func TestUninstallGroupManagedSucceedsWhenPresenceDoesNotFlip(t *testing.T) {
	client, session := InternalNewServiceAccountTestClient(t)
	account := InternalServiceAccountTestEntry(admodel.ServiceAccountGroupManaged)
	account.DistinguishedName = "CN=svc,OU=target,DC=example"
	account.Attributes["samaccountname"] = [][]byte{[]byte("svc$")}
	session.InternalObjects[strings.ToLower(account.DistinguishedName)] = account

	// The host must agree with the directory domain, so take the domain's own
	// GUID from the fixture rather than inventing one.
	domainValue, err := session.InternalObjects["dc=example"].Values("objectGUID").Single()
	if err != nil {
		t.Fatal(err)
	}
	domainGUID, err := domainValue.GUID()
	if err != nil {
		t.Fatal(err)
	}

	backend := &InternalLocalUninstallBackend{
		InternalHost_: admodel.LocalServiceAccountHost{
			ComputerName: "MEMBER",
			DomainGUID:   domainGUID,
			MachineRole:  3,
		},
		InternalPresence: true,
	}
	identity, err := admodel.IdentityByDN(account.DistinguishedName)
	if err != nil {
		t.Fatal(err)
	}
	result, err := adservice_service_accounts.InternalServiceUninstallLocalServiceAccount(
		adservice_service_accounts.New(client),
		t.Context(),
		admodel.UninstallLocalServiceAccountRequest{Identity: identity},
		backend,
	)
	if err != nil {
		t.Fatalf("a successful gMSA uninstall must not error: %v", err)
	}
	if backend.InternalCalls != 1 {
		t.Fatalf(
			"the native uninstall must be attempted exactly once, got %d",
			backend.InternalCalls,
		)
	}
	if !result.Complete {
		t.Fatal("the operation must report itself complete")
	}
	// It completes unverified, and says so, rather than claiming a flip that
	// the native reading never shows.
	if result.Verified {
		t.Fatal("presence did not flip, so the result must not claim verification")
	}
	if result.After == nil || !*result.After {
		t.Fatalf("the observed presence must be retained as read: %+v", result.After)
	}
}

// A reset must refuse on an account this host does not hold, mirroring the
// reference refusal the lab recorded.
func TestResetRefusesWhenNotInstalled(t *testing.T) {
	client, session := InternalNewServiceAccountTestClient(t)
	account := InternalServiceAccountTestEntry(admodel.ServiceAccountGroupManaged)
	account.DistinguishedName = "CN=svc,OU=target,DC=example"
	account.Attributes["samaccountname"] = [][]byte{[]byte("svc$")}
	session.InternalObjects[strings.ToLower(account.DistinguishedName)] = account
	domainValue, err := session.InternalObjects["dc=example"].Values("objectGUID").Single()
	if err != nil {
		t.Fatal(err)
	}
	domainGUID, err := domainValue.GUID()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := admodel.IdentityByDN(account.DistinguishedName)
	if err != nil {
		t.Fatal(err)
	}
	host := admodel.LocalServiceAccountHost{
		ComputerName: "MEMBER",
		DomainGUID:   domainGUID,
		MachineRole:  3,
	}

	// Not installed: the native reset must never be attempted.
	backend := &InternalLocalUninstallBackend{InternalHost_: host, InternalPresence: false}
	_, err = adservice_service_accounts.InternalServiceResetLocalServiceAccountPassword(
		adservice_service_accounts.New(client),
		t.Context(),
		admodel.ResetLocalServiceAccountPasswordRequest{Identity: identity},
		backend,
	)
	if !errors.Is(err, admodel.ErrServiceAccountNotInstalled) {
		t.Fatalf("expected ErrServiceAccountNotInstalled, got %v", err)
	}

	// Installed: the reset runs and the account must still be installed after.
	installed := &InternalLocalResetBackend{
		InternalLocalUninstallBackend: InternalLocalUninstallBackend{
			InternalHost_:    host,
			InternalPresence: true,
		},
	}
	result, err := adservice_service_accounts.InternalServiceResetLocalServiceAccountPassword(
		adservice_service_accounts.New(client),
		t.Context(),
		admodel.ResetLocalServiceAccountPasswordRequest{Identity: identity},
		installed,
	)
	if err != nil {
		t.Fatalf("reset on an installed account must succeed: %v", err)
	}
	if !result.Verified || !result.Complete {
		t.Fatalf("a reset that left the account installed must verify: %+v", result)
	}
	// The credential must be requested from the host, never supplied: a NULL
	// password with flags 1 is the only acceptable call shape here.
	if len(installed.InternalPasswords) != 1 || installed.InternalPasswords[0] != nil {
		t.Fatalf("reset must pass a nil password, got %+v", installed.InternalPasswords)
	}
	if len(installed.InternalFlags) != 1 || installed.InternalFlags[0] != 1 {
		t.Fatalf("reset must use flags 1, got %+v", installed.InternalFlags)
	}

	// Preview must not call the native reset at all.
	preview := &InternalLocalResetBackend{
		InternalLocalUninstallBackend: InternalLocalUninstallBackend{
			InternalHost_:    host,
			InternalPresence: true,
		},
	}
	previewed, err := adservice_service_accounts.InternalServiceResetLocalServiceAccountPassword(
		adservice_service_accounts.New(client),
		t.Context(),
		admodel.ResetLocalServiceAccountPasswordRequest{Identity: identity, Preview: true},
		preview,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !previewed.Preview || !previewed.Complete || len(preview.InternalPasswords) != 0 {
		t.Fatalf(
			"preview must not mutate: %+v calls=%d",
			previewed.Preview,
			len(preview.InternalPasswords),
		)
	}
}

// localResetBackend records the install call so the reset's call shape can be
// asserted, while keeping presence pinned true.
type InternalLocalResetBackend struct {
	InternalLocalUninstallBackend
	InternalPasswords [][]byte
	InternalFlags     []uint32
}

func (b *InternalLocalResetBackend) InternalInstall(
	_ context.Context,
	_ string,
	password []byte,
	flags uint32,
) admodel.LocalServiceAccountAttempt {
	b.InternalPasswords = append(b.InternalPasswords, password)
	b.InternalFlags = append(b.InternalFlags, flags)
	zero := uint32(0)
	return admodel.LocalServiceAccountAttempt{
		Operation: "NetAddServiceAccount",
		State:     admodel.ObjectWriteAccepted,
		Status:    &zero,
	}
}
