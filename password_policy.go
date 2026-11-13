package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

var (
	ErrInvalidPasswordPolicy    = errors.New("invalid default domain password policy")
	ErrPasswordPolicyTarget     = errors.New("password policy requires the connected AD DS server's default domain")
	ErrPasswordPolicyReadOnly   = errors.New("password policy update requires a synchronized writable domain controller")
	ErrPasswordPolicyPermission = errors.New("password policy access denied")
	ErrPasswordPolicyChanged    = errors.New("password policy changed before the conditional update")
	ErrPasswordPolicyUncertain  = errors.New("password policy write outcome is unknown; reconcile before another write")
	ErrPasswordPolicyReadback   = errors.New("password policy readback did not verify the requested state")
)

// DomainPasswordPolicy is the policy on the domain NC root, not a resultant
// user policy or a GPO. Reads reflect the connected server's replica.
type DomainPasswordPolicy struct {
	DomainDN                 string
	MaxPasswordAge           PolicyInterval
	MinPasswordAge           PolicyInterval
	LockoutDuration          PolicyInterval
	LockoutObservationWindow PolicyInterval
	LockoutThreshold         uint16
	MinPasswordLength        uint16
	PasswordHistoryCount     uint16
	// PasswordProperties preserves every pwdProperties bit, including unknown
	// ones. Updates expose only the complexity and reversible-encryption bits.
	PasswordProperties uint32
	UASCompatible      bool
}

func (p DomainPasswordPolicy) ComplexityEnabled() bool { return p.PasswordProperties&1 != 0 }
func (p DomainPasswordPolicy) ReversibleEncryptionEnabled() bool {
	return p.PasswordProperties&0x10 != 0
}

// DomainPasswordPolicyUpdate is a patch: nil means omitted; non-nil zero or
// false is explicit. MaxPasswordAge zero follows the PowerShell cmdlet's
// convention and writes PolicyNever. Other intervals preserve zero literally;
// use PolicyNever explicitly for an indefinite lockout.
type DomainPasswordPolicyUpdate struct {
	MaxPasswordAge              *PolicyInterval
	MinPasswordAge              *PolicyInterval
	LockoutDuration             *PolicyInterval
	LockoutObservationWindow    *PolicyInterval
	LockoutThreshold            *uint16
	MinPasswordLength           *uint16
	PasswordHistoryCount        *uint16
	ComplexityEnabled           *bool
	ReversibleEncryptionEnabled *bool
}

// Validate checks request bounds without reading current policy. Relationships
// involving omitted values and uASCompat are checked against the server's data.
func (u DomainPasswordPolicyUpdate) Validate() error {
	present := u.LockoutThreshold != nil || u.MinPasswordLength != nil || u.PasswordHistoryCount != nil || u.ComplexityEnabled != nil || u.ReversibleEncryptionEnabled != nil
	for _, value := range []*PolicyInterval{u.MaxPasswordAge, u.MinPasswordAge, u.LockoutDuration, u.LockoutObservationWindow} {
		if value != nil {
			present = true
			if *value > PolicyNever {
				return ErrPolicyIntervalRange
			}
		}
	}
	if !present || (u.MinPasswordLength != nil && *u.MinPasswordLength > 256) || (u.PasswordHistoryCount != nil && *u.PasswordHistoryCount > 1024) {
		return ErrInvalidPasswordPolicy
	}
	return nil
}

type PasswordPolicyWriteState uint8

const (
	PasswordPolicyWriteNotAttempted PasswordPolicyWriteState = iota
	PasswordPolicyWriteAccepted
	PasswordPolicyWriteRejected
	PasswordPolicyWriteUncertain
)

// DomainPasswordPolicyUpdateResult preserves known mutation status even if
// readback fails. No-op updates are verified with WriteNotAttempted. Before and
// After may be partial on error; After is populated only by an actual read.
type DomainPasswordPolicyUpdateResult struct {
	Before     DomainPasswordPolicy
	After      DomainPasswordPolicy
	WriteState PasswordPolicyWriteState
	WriteError error
	Verified   bool
}

// DefaultDomainPasswordPolicy reads the default domain of the pinned server.
// Config.Partition, if set, must match that domain; application partitions and
// other domains are rejected. AD LDS is unsupported. RODC reads are allowed.
func (c *Client) DefaultDomainPasswordPolicy(ctx context.Context) (DomainPasswordPolicy, error) {
	var result DomainPasswordPolicy
	err := c.read(ctx, func(bounded context.Context) error {
		dn, err := passwordPolicyTarget(bounded, c.session, c.config.Partition, false)
		if err != nil {
			return err
		}
		result, _, err = readPasswordPolicy(bounded, c.session, dn, false)
		return err
	})
	return result, passwordPolicyError(err)
}

// UpdateDefaultDomainPasswordPolicy submits at most one atomic, conditional
// LDAP Modify. Only changed attributes are written; exact old values guard
// against lost updates, including changes to unrelated pwdProperties bits.
// Permission failures, concurrent edits, and uncertain responses are never
// retried. A lost response retires the LDAP session. Successful readback checks
// this server's replica, not replication convergence or a user's effective PSO.
func (c *Client) UpdateDefaultDomainPasswordPolicy(ctx context.Context, update DomainPasswordPolicyUpdate) (DomainPasswordPolicyUpdateResult, error) {
	var result DomainPasswordPolicyUpdateResult
	if err := update.Validate(); err != nil {
		return result, err
	}
	err := c.read(ctx, func(bounded context.Context) error {
		session, ok := c.session.(ldapModifySession)
		if !ok {
			return ErrUnsupported
		}
		dn, err := passwordPolicyTarget(bounded, session, c.config.Partition, true)
		if err != nil {
			return err
		}
		before, raw, err := readPasswordPolicy(bounded, session, dn, true)
		result.Before = before
		if err != nil {
			return err
		}
		after, err := mergePasswordPolicy(before, update)
		if err != nil {
			return err
		}
		mods := passwordPolicyModifications(before, after, raw)
		if len(mods) == 0 {
			result.After, result.Verified = before, true
			return nil
		}
		attempt := session.ldapModify(bounded, dn, mods)
		result.WriteState = PasswordPolicyWriteState(attempt.State)
		result.WriteError = passwordPolicyError(attempt.Err)
		var native *LDAPError
		if attempt.State == ldapWriteRejected && errors.As(attempt.Err, &native) && native.Code == 16 {
			result.WriteError = errors.Join(ErrPasswordPolicyChanged, result.WriteError)
		}
		if attempt.State == ldapWriteUncertain {
			result.WriteError = errors.Join(ErrPasswordPolicyUncertain, result.WriteError)
		}
		if attempt.State != ldapWriteAccepted || attempt.Err != nil {
			return result.WriteError
		}
		result.After, _, err = readPasswordPolicy(bounded, session, dn, true)
		if err != nil {
			return errors.Join(ErrPasswordPolicyReadback, err)
		}
		if result.After != after {
			return ErrPasswordPolicyReadback
		}
		result.Verified = true
		return nil
	})
	return result, passwordPolicyError(err)
}

func passwordPolicyTarget(ctx context.Context, session directorySession, partition string, write bool) (string, error) {
	attrs, err := session.baseObject(ctx, "", []string{"supportedCapabilities", "defaultNamingContext", "dsServiceName", "isSynchronized"})
	if err != nil {
		return "", err
	}
	root, err := decodeRootDSE(attrs, nil)
	if err != nil {
		return "", err
	}
	if err := root.Capabilities().RequireADDS("default domain password policy"); err != nil {
		return "", err
	}
	if root.DefaultNamingContext == nil || *root.DefaultNamingContext == "" || (partition != "" && !strings.EqualFold(partition, *root.DefaultNamingContext)) {
		return "", ErrPasswordPolicyTarget
	}
	if !write {
		return *root.DefaultNamingContext, nil
	}
	if root.IsSynchronized == nil || !*root.IsSynchronized || root.Capabilities().Has("1.2.840.113556.1.4.1920") || root.DSServiceName == nil || *root.DSServiceName == "" {
		return "", ErrPasswordPolicyReadOnly
	}
	dsa, err := session.baseObject(ctx, *root.DSServiceName, []string{"objectClass", "msDS-isRODC"})
	if err != nil {
		return "", err
	}
	d := rootDSEDecoder{attributes: dsa}
	readOnly := decodeScalar(&d, "msDS-isRODC", parseLDAPBool)
	classes := d.texts("objectClass")
	if readOnly == nil || *readOnly || len(d.errors) != 0 || !slices.ContainsFunc(classes, func(class string) bool { return strings.EqualFold(class, "nTDSDSA") }) {
		return "", errors.Join(ErrPasswordPolicyReadOnly, errors.Join(d.errors...))
	}
	return *root.DefaultNamingContext, nil
}

func passwordPolicyAttributes() []string {
	return []string{"distinguishedName", "objectClass", "objectSID", "instanceType", "maxPwdAge", "minPwdAge", "lockoutDuration", "lockOutObservationWindow", "lockoutThreshold", "minPwdLength", "pwdHistoryLength", "pwdProperties", "uASCompat"}
}

func readPasswordPolicy(ctx context.Context, session directorySession, dn string, write bool) (DomainPasswordPolicy, map[string][][]byte, error) {
	attrs, readErr := session.baseObject(ctx, dn, passwordPolicyAttributes())
	d := rootDSEDecoder{attributes: attrs}
	result := DomainPasswordPolicy{}
	name := d.text("distinguishedName")
	classes := d.texts("objectClass")
	instance := decodeScalar(&d, "instanceType", parseUint32)
	sid := attrs["objectsid"]
	if name == nil || !strings.EqualFold(*name, dn) || instance == nil || *instance&1 == 0 || !slices.ContainsFunc(classes, func(class string) bool { return strings.EqualFold(class, "domainDNS") }) || len(sid) != 1 || !validDomainSID(sid[0]) {
		return result, attrs, errors.Join(readErr, ErrPasswordPolicyTarget, errors.Join(d.errors...))
	}
	result.DomainDN = *name
	if write && *instance&4 == 0 {
		return result, attrs, errors.Join(readErr, ErrPasswordPolicyReadOnly)
	}
	for _, field := range []struct {
		name   string
		target *PolicyInterval
	}{
		{"maxPwdAge", &result.MaxPasswordAge}, {"minPwdAge", &result.MinPasswordAge}, {"lockoutDuration", &result.LockoutDuration}, {"lockOutObservationWindow", &result.LockoutObservationWindow},
	} {
		value := decodeScalar(&d, field.name, parsePolicyInterval)
		if value == nil {
			d.invalid(field.name)
		} else {
			*field.target = *value
		}
	}
	for _, field := range []struct {
		name   string
		target *uint16
	}{
		{"lockoutThreshold", &result.LockoutThreshold}, {"minPwdLength", &result.MinPasswordLength}, {"pwdHistoryLength", &result.PasswordHistoryCount},
	} {
		value := decodeScalar(&d, field.name, func(text string) (uint16, error) {
			number, err := strconv.ParseUint(text, 10, 16)
			return uint16(number), err
		})
		if value == nil {
			d.invalid(field.name)
		} else {
			*field.target = *value
		}
	}
	flags := decodeScalar(&d, "pwdProperties", parsePasswordProperties)
	if flags == nil {
		d.invalid("pwdProperties")
	} else {
		result.PasswordProperties = *flags
	}
	compat := decodeScalar(&d, "uASCompat", parseUint32)
	if compat == nil {
		d.invalid("uASCompat")
	} else {
		result.UASCompatible = *compat != 0
	}
	return result, attrs, errors.Join(readErr, errors.Join(d.errors...))
}

func parsePasswordProperties(text string) (uint32, error) {
	number, err := strconv.ParseInt(text, 10, 64)
	if err != nil || number < math.MinInt32 || number > math.MaxUint32 {
		return 0, ErrInvalidPasswordPolicy
	}
	return uint32(number), nil
}

func mergePasswordPolicy(before DomainPasswordPolicy, update DomainPasswordPolicyUpdate) (DomainPasswordPolicy, error) {
	after := before
	for _, field := range []struct {
		source *PolicyInterval
		target *PolicyInterval
	}{
		{update.MaxPasswordAge, &after.MaxPasswordAge}, {update.MinPasswordAge, &after.MinPasswordAge}, {update.LockoutDuration, &after.LockoutDuration}, {update.LockoutObservationWindow, &after.LockoutObservationWindow},
	} {
		if field.source != nil {
			*field.target = *field.source
		}
	}
	if update.MaxPasswordAge != nil && *update.MaxPasswordAge == 0 {
		after.MaxPasswordAge = PolicyNever
	}
	for _, field := range []struct {
		source *uint16
		target *uint16
	}{
		{update.LockoutThreshold, &after.LockoutThreshold}, {update.MinPasswordLength, &after.MinPasswordLength}, {update.PasswordHistoryCount, &after.PasswordHistoryCount},
	} {
		if field.source != nil {
			*field.target = *field.source
		}
	}
	for _, flag := range []struct {
		source *bool
		mask   uint32
	}{{update.ComplexityEnabled, 1}, {update.ReversibleEncryptionEnabled, 0x10}} {
		if flag.source != nil {
			if *flag.source {
				after.PasswordProperties |= flag.mask
			} else {
				after.PasswordProperties &^= flag.mask
			}
		}
	}
	if after.LockoutObservationWindow > after.LockoutDuration || after.MinPasswordLength > 256 || (after.UASCompatible && after.MinPasswordLength > 14) || after.PasswordHistoryCount > 1024 {
		return after, fmt.Errorf("%w: lockout window, password length, history, or uASCompat constraint", ErrInvalidPasswordPolicy)
	}
	return after, nil
}

type passwordPolicyValue struct{ name, value string }

func passwordPolicyValues(policy DomainPasswordPolicy) []passwordPolicyValue {
	return []passwordPolicyValue{
		{"maxPwdAge", formatPolicyInterval(policy.MaxPasswordAge)}, {"minPwdAge", formatPolicyInterval(policy.MinPasswordAge)},
		{"lockoutDuration", formatPolicyInterval(policy.LockoutDuration)}, {"lockOutObservationWindow", formatPolicyInterval(policy.LockoutObservationWindow)},
		{"lockoutThreshold", strconv.FormatUint(uint64(policy.LockoutThreshold), 10)}, {"minPwdLength", strconv.FormatUint(uint64(policy.MinPasswordLength), 10)},
		{"pwdHistoryLength", strconv.FormatUint(uint64(policy.PasswordHistoryCount), 10)}, {"pwdProperties", strconv.FormatInt(int64(int32(policy.PasswordProperties)), 10)},
	}
}

func passwordPolicyModifications(before, after DomainPasswordPolicy, raw map[string][][]byte) []ldapModification {
	previous := passwordPolicyValues(before)
	var mods []ldapModification
	for i, desired := range passwordPolicyValues(after) {
		if desired.value == previous[i].value {
			continue
		}
		// Deletion checks the exact previously read value in the same atomic
		// request as the addition. There is no unconditional replacement retry.
		mods = append(mods, ldapModification{1, desired.name, slices.Clone(raw[strings.ToLower(desired.name)][0])}, ldapModification{0, desired.name, []byte(desired.value)})
	}
	return mods
}

func passwordPolicyError(err error) error {
	var native *LDAPError
	if errors.As(err, &native) {
		switch native.Code {
		case 50:
			if !errors.Is(err, ErrPasswordPolicyPermission) {
				return errors.Join(ErrPasswordPolicyPermission, err)
			}
		}
	}
	return err
}
