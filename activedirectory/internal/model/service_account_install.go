package model

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

var (
	ErrInvalidServiceAccountInstall = errors.New("invalid local service account operation")
	ErrServiceAccountHost           = errors.New(
		"service account and executing host must belong to the same joined AD DS domain",
	)
	ErrServiceAccountOtherHost = errors.New(
		"standalone service account has another visible host; explicit Force is required",
	)
	ErrServiceAccountLocalPermission = errors.New(
		"local managed service account permission denied",
	)
	ErrServiceAccountLocalUncertain = errors.New(
		"local service account outcome is uncertain; reconcile before another operation",
	)
	ErrServiceAccountLocalObservation = errors.New(
		"local service account observation did not verify the requested state",
	)
)

// ServiceAccountPasswordPrompt is the non-interactive SDK equivalent of
// PromptForPassword. The callback owns its UI. Returned bytes transfer to the
// SDK and are erased on every exit; do not return a shared or reusable buffer.
// Explicit AccountPassword takes precedence. Neither form is used for gMSAs.
type ServiceAccountPasswordPrompt func(context.Context, ServiceAccount) ([]byte, error)

type InstallLocalServiceAccountRequest struct {
	Identity  Identity
	Partition string
	// Force permits a standalone account with a visible association to another
	// computer. It is not a retry flag or a native flag0 directory-create request.
	Force           bool
	AccountPassword []byte                       `json:"-"`
	PasswordPrompt  ServiceAccountPasswordPrompt `json:"-"`
	// Preview performs read-only preparation without calling the prompt or a
	// native mutation. It does not reserve an identity or guarantee permissions.
	Preview bool
}

func (InstallLocalServiceAccountRequest) String() string {
	return "InstallLocalServiceAccountRequest{redacted}"
}

func (InstallLocalServiceAccountRequest) GoString() string {
	return "InstallLocalServiceAccountRequest{redacted}"
}

func (InstallLocalServiceAccountRequest) MarshalJSON() ([]byte, error) {
	return []byte(`{"redacted":true}`), nil
}

func (InstallLocalServiceAccountRequest) MarshalText() ([]byte, error) {
	return []byte("InstallLocalServiceAccountRequest{redacted}"), nil
}

type UninstallLocalServiceAccountRequest struct {
	Identity  Identity
	Partition string
	// On the specific known STATUS_NO_SUCH_DOMAIN reply, allow the documented
	// offline removal phase. No fallback follows cancellation or uncertainty.
	ForceRemoveLocal bool
	Preview          bool
}

type LocalServiceAccountHost struct {
	ComputerName string
	DomainGUID   GUID
	DomainDNS    string
	MachineRole  uint32
	ReadOnly     bool
}

// Native status preserves the NTSTATUS bit pattern. It is never interpreted as
// GetLastError, and formatted errors never include account/password text.
type LocalServiceAccountNativeError struct {
	Operation string
	Status    uint32
}

func (e *LocalServiceAccountNativeError) Error() string {
	return fmt.Sprintf("%s: NTSTATUS 0x%08X", e.Operation, e.Status)
}

func (e *LocalServiceAccountNativeError) Is(target error) bool {
	return target == ErrServiceAccountLocalPermission &&
		(e.Status == 0xc0000022 || e.Status == 0xc0000061)
}

type LocalServiceAccountAttempt struct {
	Operation string
	Flags     uint32
	State     ObjectWriteState
	Status    *uint32
	Error     error
}

// Directory contains the explicit LDAP resolution; Host always identifies the
// executing Windows machine. LDAP credentials are never forwarded to Net APIs.
// Before/After describe Netlogon-store presence, not password validity or a
// guarantee that a running service cannot recreate a gMSA cache entry.
type LocalServiceAccountResult struct {
	Host                                  LocalServiceAccountHost
	Directory                             IdentityResult
	Domain                                IdentityResult
	HostComputer                          IdentityResult
	Account                               *ServiceAccount
	NativeAccountName                     string
	HostLinks                             []ComputerServiceAccountRange
	HostLinksComplete, HostLinksReturned  bool
	OtherHosts                            []string
	Before, After                         *bool
	Attempts                              []LocalServiceAccountAttempt
	PasswordOptionsIgnored                bool
	Preview, Prepared, Verified, Complete bool
	// A synchronous native operation can modify both local state and an sMSA
	// directory link before returning an error. No call is automatically replayed.
	PartialEffectsPossible bool
}

type InternalLocalServiceAccountBackend interface {
	InternalHost(context.Context) (LocalServiceAccountHost, error)
	InternalInstalled(context.Context, string) (*bool, error)
	InternalInstall(context.Context, string, []byte, uint32) LocalServiceAccountAttempt
	InternalUninstall(context.Context, string, uint32) LocalServiceAccountAttempt
}

// Serialize this SDK process's local workflows; external tools and other
// processes remain concurrent. Synchronous native calls are allowed to finish
// before their owned input buffers are erased, even after context cancellation.
var InternalLocalServiceAccountGate = make(chan struct{}, 1)

func InternalLocalServiceAccountName(sam string) (string, error) {
	name := strings.TrimSuffix(sam, "$")
	if name == "" || !InternalValidDirectoryText(name) || strings.ContainsAny(name, `\/@$`) ||
		len(utf16.Encode([]rune(name))) > 15 {
		return "", ErrInvalidServiceAccountInstall
	}
	return name, nil
}

func InternalCollectLocalServiceAccountHosts(
	ctx context.Context,
	session InternalDirectorySession,
	result *LocalServiceAccountResult,
) error {
	reader, ok := session.(InternalServiceAccountRangeReader)
	if !ok {
		return ErrUnsupported
	}
	guid, usn, err := InternalServiceAccountLinkVersion(*result.Directory.Object)
	if err != nil {
		return err
	}
	host, err := InternalParseIdentityDN(result.HostComputer.Object.DistinguishedName)
	if err != nil {
		return err
	}
	start, remaining, count := uint64(0), 4<<20, 0
	for {
		if err = context.Cause(ctx); err != nil {
			return err
		}
		if len(result.HostLinks) >= 100 || count >= 1000 {
			return ErrServiceAccountAssociationLimit
		}
		property := fmt.Sprintf(
			"msDS-HostServiceAccountBL;range=%d-%d",
			start,
			start+uint64(min(100, 1000-count))-1,
		)
		attrs, readErr := reader.InternalRangedBaseObject(
			ctx,
			InternalObjectGUIDTarget(guid),
			[]string{property, "objectGUID", "uSNChanged"},
		)
		result.HostLinks = append(
			result.HostLinks,
			ComputerServiceAccountRange{Property: property, Attributes: attrs, Error: readErr},
		)
		for name, values := range attrs {
			if len(name) > remaining {
				return errors.Join(readErr, ErrServiceAccountAssociationLimit)
			}
			remaining -= len(name)
			for _, v := range values {
				if err = context.Cause(ctx); err != nil {
					return errors.Join(readErr, err)
				}
				if len(v) > remaining {
					return errors.Join(readErr, ErrServiceAccountAssociationLimit)
				}
				remaining -= len(v)
			}
		}
		values, next, terminal, present, err := InternalDirectoryReferenceRange(
			attrs,
			"msDS-HostServiceAccountBL",
			start,
		)
		result.HostLinksReturned = result.HostLinksReturned || present
		count += len(values)
		if count > 1000 {
			return errors.Join(readErr, err, ErrServiceAccountAssociationLimit)
		}
		for _, v := range values {
			if cause := context.Cause(ctx); cause != nil {
				return errors.Join(readErr, err, cause)
			}
			text, e := NewRawValue(v).Text()
			if e != nil {
				err = errors.Join(err, e)
				continue
			}
			dn, e := InternalParseIdentityDN(text)
			if e != nil {
				err = errors.Join(err, e)
				continue
			}
			if !InternalSameIdentityDN(dn, host) {
				result.OtherHosts = append(result.OtherHosts, text)
			}
		}
		actualGUID, actualUSN, e := InternalServiceAccountLinkVersion(Object{Attributes: attrs})
		if e == nil && (actualGUID != guid || actualUSN != usn) {
			e = ErrObjectConcurrency
		}
		if e = errors.Join(readErr, err, e); e != nil {
			return e
		}
		if terminal {
			result.HostLinksComplete = true
			return nil
		}
		start = next
	}
}

func InternalLockLocalServiceAccount(ctx context.Context) error {
	select {
	case InternalLocalServiceAccountGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func InternalLocalServiceAccountAttemptError(attempt LocalServiceAccountAttempt) error {
	if attempt.State == ObjectWriteUncertain {
		return errors.Join(ErrServiceAccountLocalUncertain, attempt.Error)
	}
	if attempt.Error != nil {
		return attempt.Error
	}
	if attempt.Status == nil || attempt.State == ObjectWriteNotAttempted {
		return ErrInvalidResult
	}
	if *attempt.Status != 0 {
		return &LocalServiceAccountNativeError{
			Operation: attempt.Operation,
			Status:    *attempt.Status,
		}
	}
	if attempt.State != ObjectWriteAccepted {
		return ErrInvalidResult
	}
	return nil
}
