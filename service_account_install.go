package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

var (
	ErrInvalidServiceAccountInstall   = errors.New("invalid local service account operation")
	ErrServiceAccountHost             = errors.New("service account and executing host must belong to the same joined AD DS domain")
	ErrServiceAccountOtherHost        = errors.New("standalone service account has another visible host; explicit Force is required")
	ErrServiceAccountLocalPermission  = errors.New("local managed service account permission denied")
	ErrServiceAccountLocalUncertain   = errors.New("local service account outcome is uncertain; reconcile before another operation")
	ErrServiceAccountLocalObservation = errors.New("local service account observation did not verify the requested state")
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
	return target == ErrServiceAccountLocalPermission && (e.Status == 0xc0000022 || e.Status == 0xc0000061)
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

type localServiceAccountBackend interface {
	host(context.Context) (LocalServiceAccountHost, error)
	installed(context.Context, string) (*bool, error)
	install(context.Context, string, []byte, uint32) LocalServiceAccountAttempt
	uninstall(context.Context, string, uint32) LocalServiceAccountAttempt
}

// Serialize this SDK process's local workflows; external tools and other
// processes remain concurrent. Synchronous native calls are allowed to finish
// before their owned input buffers are erased, even after context cancellation.
var localServiceAccountGate = make(chan struct{}, 1)

func (c *Client) InstallLocalServiceAccount(ctx context.Context, request InstallLocalServiceAccountRequest) (LocalServiceAccountResult, error) {
	return c.installLocalServiceAccount(ctx, request, newLocalServiceAccountBackend())
}
func (c *Client) UninstallLocalServiceAccount(ctx context.Context, request UninstallLocalServiceAccountRequest) (LocalServiceAccountResult, error) {
	return c.uninstallLocalServiceAccount(ctx, request, newLocalServiceAccountBackend())
}

func localServiceAccountName(sam string) (string, error) {
	name := strings.TrimSuffix(sam, "$")
	if name == "" || !validDirectoryText(name) || strings.ContainsAny(name, `\/@$`) || len(utf16.Encode([]rune(name))) > 15 {
		return "", ErrInvalidServiceAccountInstall
	}
	return name, nil
}
func (c *Client) prepareLocalServiceAccount(ctx context.Context, backend localServiceAccountBackend, identity Identity, partition string, install, force bool, result *LocalServiceAccountResult) error {
	options := accountControlIdentity(identity, partition, []string{"objectClass", "objectGUID", "objectSid", "name", "sAMAccountName", "uSNChanged"})
	if err := validateIdentityOperation(identity, options); err != nil {
		return err
	}
	var err error
	result.Host, err = backend.host(ctx)
	if err != nil {
		return err
	}
	if result.Host.ComputerName == "" || result.Host.DomainGUID == (GUID{}) || result.Host.ReadOnly || (result.Host.MachineRole != 1 && result.Host.MachineRole != 3 && result.Host.MachineRole != 4 && result.Host.MachineRole != 5) {
		return ErrServiceAccountHost
	}
	return c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if err = root.Capabilities().RequireADDS("LocalServiceAccount"); err != nil {
			return err
		}
		if c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269 {
			return ErrServiceAccountHost
		}
		result.Directory, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if err != nil {
			return err
		}
		account, err := decodeServiceAccount(*result.Directory.Object)
		result.Account = &account
		if err != nil {
			return err
		}
		if account.SAMAccountName == nil {
			return ErrAttributeUnavailable
		}
		result.NativeAccountName, err = localServiceAccountName(*account.SAMAccountName)
		if err != nil {
			return err
		}
		domain, err := IdentityByDN(result.Directory.Partition)
		if err != nil {
			return err
		}
		result.Domain, err = resolveIdentitySession(ctx, c.session, c.config, root, domain, ResolveIdentityOptions{Partition: result.Directory.Partition, Properties: []string{"objectGUID", "objectClass"}})
		if err != nil {
			return err
		}
		value, err := result.Domain.Object.Values("objectGUID").Single()
		if err != nil {
			return err
		}
		guid, err := value.GUID()
		if err != nil {
			return err
		}
		if guid != result.Host.DomainGUID {
			return ErrServiceAccountHost
		}
		if install && account.Kind == ServiceAccountStandalone {
			hostID, err := IdentityByAccountName(result.Host.ComputerName + "$")
			if err != nil {
				return err
			}
			result.HostComputer, err = resolveIdentitySession(ctx, c.session, c.config, root, hostID, computerIdentityOptions(hostID, result.Directory.Partition, nil))
			if err != nil {
				return err
			}
			if err = computerClass(*result.HostComputer.Object); err != nil {
				return err
			}
			if err = collectLocalServiceAccountHosts(ctx, c.session, result); err != nil {
				return err
			}
			if len(result.OtherHosts) > 0 && !force {
				return ErrServiceAccountOtherHost
			}
		}
		result.Prepared = true
		return nil
	})
}

func collectLocalServiceAccountHosts(ctx context.Context, session directorySession, result *LocalServiceAccountResult) error {
	reader, ok := session.(serviceAccountRangeReader)
	if !ok {
		return ErrUnsupported
	}
	guid, usn, err := serviceAccountLinkVersion(*result.Directory.Object)
	if err != nil {
		return err
	}
	host, err := parseIdentityDN(result.HostComputer.Object.DistinguishedName)
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
		property := fmt.Sprintf("msDS-HostServiceAccountBL;range=%d-%d", start, start+uint64(min(100, 1000-count))-1)
		attrs, readErr := reader.rangedBaseObject(ctx, objectGUIDTarget(guid), []string{property, "objectGUID", "uSNChanged"})
		result.HostLinks = append(result.HostLinks, ComputerServiceAccountRange{Property: property, Attributes: attrs, Error: readErr})
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
		values, next, terminal, present, err := directoryReferenceRange(attrs, "msDS-HostServiceAccountBL", start)
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
			dn, e := parseIdentityDN(text)
			if e != nil {
				err = errors.Join(err, e)
				continue
			}
			if !sameIdentityDN(dn, host) {
				result.OtherHosts = append(result.OtherHosts, text)
			}
		}
		actualGUID, actualUSN, e := serviceAccountLinkVersion(Object{Attributes: attrs})
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

func lockLocalServiceAccount(ctx context.Context) error {
	select {
	case localServiceAccountGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}
func localServiceAccountAttemptError(attempt LocalServiceAccountAttempt) error {
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
		return &LocalServiceAccountNativeError{Operation: attempt.Operation, Status: *attempt.Status}
	}
	if attempt.State != ObjectWriteAccepted {
		return ErrInvalidResult
	}
	return nil
}
func (c *Client) installLocalServiceAccount(ctx context.Context, request InstallLocalServiceAccountRequest, backend localServiceAccountBackend) (result LocalServiceAccountResult, err error) {
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	if ctx == nil {
		return result, ErrInvalidServiceAccountInstall
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	if err = lockLocalServiceAccount(bounded); err != nil {
		return
	}
	defer func() { <-localServiceAccountGate }()
	if err = c.prepareLocalServiceAccount(bounded, backend, request.Identity, request.Partition, true, request.Force, &result); err != nil {
		return
	}
	result.Before, err = backend.installed(bounded, result.NativeAccountName)
	if err != nil {
		return
	}
	if result.Before == nil {
		return result, ErrInvalidResult
	}
	result.Preview = request.Preview
	result.PasswordOptionsIgnored = result.Account.Kind == ServiceAccountGroupManaged && (request.AccountPassword != nil || request.PasswordPrompt != nil)
	if request.Preview {
		result.Complete = true
		return
	}
	var password []byte
	flags := uint32(1)
	if result.Account.Kind == ServiceAccountStandalone {
		password = request.AccountPassword
		if password == nil && request.PasswordPrompt != nil {
			password, err = request.PasswordPrompt(bounded, *result.Account)
			defer clear(password)
			if err != nil {
				return
			}
			if password == nil {
				return result, ErrInvalidServiceAccountInstall
			}
		}
		if password != nil {
			if err = validatePasswordBytes(password); err != nil {
				return
			}
			flags = 2
		}
	}
	if err = context.Cause(bounded); err != nil {
		return
	}
	attempt := backend.install(bounded, result.NativeAccountName, password, flags)
	result.Attempts = append(result.Attempts, attempt)
	result.PartialEffectsPossible = attempt.State != ObjectWriteNotAttempted
	if err = localServiceAccountAttemptError(attempt); err != nil {
		return result, errors.Join(err, context.Cause(bounded))
	}
	result.After, err = backend.installed(bounded, result.NativeAccountName)
	if err != nil {
		return result, errors.Join(ErrServiceAccountLocalObservation, err)
	}
	result.Verified = result.After != nil && *result.After
	result.Complete = result.Verified
	if !result.Verified {
		return result, ErrServiceAccountLocalObservation
	}
	return
}
func (c *Client) uninstallLocalServiceAccount(ctx context.Context, request UninstallLocalServiceAccountRequest, backend localServiceAccountBackend) (result LocalServiceAccountResult, err error) {
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	if ctx == nil {
		return result, ErrInvalidServiceAccountInstall
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	if err = lockLocalServiceAccount(bounded); err != nil {
		return
	}
	defer func() { <-localServiceAccountGate }()
	if err = c.prepareLocalServiceAccount(bounded, backend, request.Identity, request.Partition, false, false, &result); err != nil {
		return
	}
	result.Before, err = backend.installed(bounded, result.NativeAccountName)
	if err != nil {
		return
	}
	if result.Before == nil {
		return result, ErrInvalidResult
	}
	result.Preview = request.Preview
	if request.Preview {
		result.Complete = true
		return
	}
	if err = context.Cause(bounded); err != nil {
		return
	}
	attempt := backend.uninstall(bounded, result.NativeAccountName, 1)
	result.Attempts = append(result.Attempts, attempt)
	result.PartialEffectsPossible = attempt.State != ObjectWriteNotAttempted
	err = localServiceAccountAttemptError(attempt)
	if request.ForceRemoveLocal && attempt.State == ObjectWriteRejected && attempt.Error == nil && attempt.Status != nil && *attempt.Status == 0xc00000df && context.Cause(bounded) == nil {
		// This is an explicit, different offline phase after a known reply; it
		// is never used to repeat an unknown or interrupted online operation.
		attempt = backend.uninstall(bounded, result.NativeAccountName, 2)
		result.Attempts = append(result.Attempts, attempt)
		result.PartialEffectsPossible = result.PartialEffectsPossible || attempt.State != ObjectWriteNotAttempted
		err = localServiceAccountAttemptError(attempt)
	}
	if err != nil {
		return result, errors.Join(err, context.Cause(bounded))
	}
	result.After, err = backend.installed(bounded, result.NativeAccountName)
	if err != nil {
		return result, errors.Join(ErrServiceAccountLocalObservation, err)
	}
	result.Verified = result.After != nil && !*result.After
	result.Complete = result.Verified
	if !result.Verified {
		return result, ErrServiceAccountLocalObservation
	}
	return
}
