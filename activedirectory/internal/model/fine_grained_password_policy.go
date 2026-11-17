package model

import (
	"errors"
	"slices"
	"strconv"
	"strings"
)

var (
	ErrInvalidFineGrainedPolicy = errors.New("invalid fine-grained password policy")
	ErrFineGrainedPolicyTarget  = errors.New(
		"fine-grained password policy requires an AD DS domain at Windows Server 2008 functional level or later",
	)
	ErrFineGrainedPolicySubject = errors.New(
		"password policy subject must be a user or global security group in the policy domain",
	)
	ErrFineGrainedPolicyLimit   = errors.New("password policy subject retrieval exceeded its bound")
	ErrFineGrainedPolicyChanged = errors.New("password policy changed during subject retrieval")
)

// FineGrainedPasswordPolicySettings is a patch: nil omits a setting. Creation
// requires all ten settings explicitly. MaxPasswordAge zero requests PolicyNever;
// other intervals preserve zero. All values retain exact 100ns precision.
type FineGrainedPasswordPolicySettings struct {
	Precedence                                                                *int32
	ComplexityEnabled, ReversibleEncryptionEnabled                            *bool
	PasswordHistoryCount, MinPasswordLength, LockoutThreshold                 *uint16
	MinPasswordAge, MaxPasswordAge, LockoutDuration, LockoutObservationWindow *PolicyInterval
}

type FineGrainedPasswordPolicy struct {
	DistinguishedName              string
	GUID                           *GUID
	Name, Description, DisplayName *string
	Settings                       FineGrainedPasswordPolicySettings
	AppliesTo                      AttributeValues
	Raw                            Object
}

type FineGrainedPasswordPolicyResult struct {
	Policy      *FineGrainedPasswordPolicy
	Observation IdentityResult
}
type FineGrainedPasswordPoliciesResult struct {
	Policies    []FineGrainedPasswordPolicy
	Observation SearchResult
}
type FineGrainedPasswordPolicyMutationResult struct {
	Policy   *FineGrainedPasswordPolicy
	Mutation ObjectMutationResult
}

func InternalFineGrainedPolicyProperties(extra []string) []string {
	return append(
		slices.Clone(extra),
		"objectClass",
		"objectGUID",
		"name",
		"description",
		"displayName",
		"msDS-PasswordSettingsPrecedence",
		"msDS-PasswordComplexityEnabled",
		"msDS-PasswordReversibleEncryptionEnabled",
		"msDS-PasswordHistoryLength",
		"msDS-MinimumPasswordLength",
		"msDS-LockoutThreshold",
		"msDS-MinimumPasswordAge",
		"msDS-MaximumPasswordAge",
		"msDS-LockoutDuration",
		"msDS-LockoutObservationWindow",
		"msDS-PSOAppliesTo",
	)
}

func InternalFineGrainedPolicyClass(object Object) error {
	classes, state := object.Attribute("objectClass")
	if state != AttributePresent {
		return errors.Join(ErrInvalidFineGrainedPolicy, ErrAttributeUnavailable)
	}
	for _, value := range classes {
		if strings.EqualFold(string(value), "msDS-PasswordSettings") {
			return nil
		}
	}
	return ErrInvalidFineGrainedPolicy
}

func InternalDecodeFineGrainedPolicy(object Object) (FineGrainedPasswordPolicy, error) {
	policy := FineGrainedPasswordPolicy{
		DistinguishedName: object.DistinguishedName,
		Raw:               object,
		AppliesTo:         object.Values("msDS-PSOAppliesTo"),
	}
	if err := InternalFineGrainedPolicyClass(object); err != nil {
		return policy, err
	}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	policy.Name, policy.Description, policy.DisplayName = d.InternalText(
		"name",
	), d.InternalText(
		"description",
	), d.InternalText(
		"displayName",
	)
	if values, state := object.Attribute("objectGUID"); state == AttributePresent {
		if len(values) != 1 {
			d.InternalErrors = append(d.InternalErrors, ErrInvalidResult)
		} else {
			guid, err := GUIDFromBytes(values[0])
			if err != nil {
				d.InternalErrors = append(d.InternalErrors, err)
			} else {
				policy.GUID = &guid
			}
		}
	}
	policy.Settings.Precedence = InternalDecodeScalar(
		&d,
		"msDS-PasswordSettingsPrecedence",
		func(value string) (int32, error) { n, err := strconv.ParseInt(value, 10, 32); return int32(n), err },
	)
	policy.Settings.ComplexityEnabled = InternalDecodeScalar(
		&d,
		"msDS-PasswordComplexityEnabled",
		InternalParseLDAPBool,
	)
	policy.Settings.ReversibleEncryptionEnabled = InternalDecodeScalar(
		&d,
		"msDS-PasswordReversibleEncryptionEnabled",
		InternalParseLDAPBool,
	)
	for _, field := range []struct {
		InternalName  string
		InternalValue **uint16
	}{
		{"msDS-PasswordHistoryLength", &policy.Settings.PasswordHistoryCount},
		{"msDS-MinimumPasswordLength", &policy.Settings.MinPasswordLength},
		{"msDS-LockoutThreshold", &policy.Settings.LockoutThreshold},
	} {
		*field.InternalValue = InternalDecodeScalar(
			&d,
			field.InternalName,
			func(value string) (uint16, error) { n, err := strconv.ParseUint(value, 10, 16); return uint16(n), err },
		)
	}
	for _, field := range []struct {
		InternalName  string
		InternalValue **PolicyInterval
	}{
		{"msDS-MinimumPasswordAge", &policy.Settings.MinPasswordAge},
		{"msDS-MaximumPasswordAge", &policy.Settings.MaxPasswordAge},
		{"msDS-LockoutDuration", &policy.Settings.LockoutDuration},
		{"msDS-LockoutObservationWindow", &policy.Settings.LockoutObservationWindow},
	} {
		*field.InternalValue = InternalDecodeScalar(
			&d,
			field.InternalName,
			InternalParsePolicyInterval,
		)
	}
	return policy, errors.Join(d.InternalErrors...)
}

func InternalFineGrainedPolicyDomain(
	root RootDSE,
	config Config,
	partition string,
) (string, error) {
	if root.Capabilities().Type != DirectoryADDS || config.Endpoint.Port == 3268 ||
		config.Endpoint.Port == 3269 {
		return "", ErrFineGrainedPolicyTarget
	}
	if root.DomainFunctionality == nil || root.DefaultNamingContext == nil {
		return "", errors.Join(ErrFineGrainedPolicyTarget, ErrAttributeUnavailable)
	}
	if *root.DomainFunctionality < 3 {
		return "", ErrFineGrainedPolicyTarget
	}
	if partition == "" {
		partition = config.Partition
	}
	if partition == "" {
		partition = *root.DefaultNamingContext
	}
	want, err := InternalParseIdentityDN(*root.DefaultNamingContext)
	if err != nil {
		return "", err
	}
	actual, err := InternalParseIdentityDN(partition)
	if err != nil || !InternalSameIdentityDN(want, actual) {
		return "", ErrFineGrainedPolicyTarget
	}
	return *root.DefaultNamingContext, nil
}

func InternalFineGrainedPolicyContainer(domain string) string {
	return "CN=Password Settings Container,CN=System," + domain
}

func InternalFineGrainedPolicyLocation(object Object, domain string) error {
	dn, err := InternalParseIdentityDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	parent, err := InternalParseIdentityDN(InternalFineGrainedPolicyContainer(domain))
	if err != nil {
		return err
	}
	if len(dn) != len(parent)+1 || !InternalSameIdentityDN(dn[1:], parent) {
		return ErrFineGrainedPolicyTarget
	}
	return InternalFineGrainedPolicyClass(object)
}
