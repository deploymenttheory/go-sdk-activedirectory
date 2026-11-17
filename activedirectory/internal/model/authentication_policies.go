package model

import (
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalidAuthenticationPolicy = errors.New("invalid authentication policy request")
	ErrNotAuthenticationPolicy     = errors.New(
		"object is not an authentication policy in this forest's policy container",
	)
	ErrAuthenticationPolicyPrerequisite = errors.New(
		"authentication policy requires AD DS and supported schema/domain/controller functionality",
	)
	ErrAuthenticationPolicyDescriptor = errors.New(
		"descriptor is not suitable for authentication-policy control-access checks",
	)
)

// StrongNTLMPolicy preserves the stored enum, including unknown returned values.
// Rolling NTLM secrets are deprecated by Microsoft; this API never enables the
// feature implicitly and makes no claim that current clients implement it.
type StrongNTLMPolicy int32

const (
	StrongNTLMDisabled StrongNTLMPolicy = iota
	StrongNTLMOptional
	StrongNTLMRequired
)

type AuthenticationPolicy struct {
	DistinguishedName                                                             string
	GUID                                                                          *GUID
	Name, Description                                                             *string
	Enforced                                                                      *bool
	UserTGTLifetime, ComputerTGTLifetime, ServiceTGTLifetime                      *Interval100ns
	UserAllowedToAuthenticateFrom, UserAllowedToAuthenticateTo                    *RawValue
	ComputerAllowedToAuthenticateTo                                               *RawValue
	ServiceAllowedToAuthenticateFrom, ServiceAllowedToAuthenticateTo              *RawValue
	UserAllowedNTLMNetworkAuthentication, ServiceAllowedNTLMNetworkAuthentication *bool
	RollingNTLMSecret                                                             *StrongNTLMPolicy
	ProtectedFromAccidentalDeletion                                               *bool
	Raw                                                                           Object
}

type AuthenticationPolicyResult struct {
	Policy      *AuthenticationPolicy
	Observation IdentityResult
	Protection  OUProtectionResult
}

type AuthenticationPoliciesResult struct {
	Policies    []AuthenticationPolicy
	Observation SearchResult
	Protection  []OUProtectionResult
}

func InternalAuthenticationPolicyProperties(extra []string) []string {
	properties := slices.DeleteFunc(
		slices.Clone(extra),
		func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") },
	)
	return append(
		properties,
		"objectGUID",
		"objectClass",
		"name",
		"description",
		"msDS-AuthNPolicyEnforced",
		"msDS-UserTGTLifetime",
		"msDS-ComputerTGTLifetime",
		"msDS-ServiceTGTLifetime",
		"msDS-UserAllowedToAuthenticateFrom",
		"msDS-UserAllowedToAuthenticateTo",
		"msDS-ComputerAllowedToAuthenticateTo",
		"msDS-ServiceAllowedToAuthenticateFrom",
		"msDS-ServiceAllowedToAuthenticateTo",
		"msDS-UserAllowedNTLMNetworkAuthentication",
		"msDS-ServiceAllowedNTLMNetworkAuthentication",
		"msDS-StrongNTLMPolicy",
	)
}

func InternalAuthenticationPolicyContainer(root RootDSE) (string, error) {
	if err := root.Capabilities().RequireADDS("AuthenticationPolicy"); err != nil {
		return "", err
	}
	if root.ConfigurationNamingContext == nil || root.DomainControllerFunctionality == nil ||
		*root.DomainControllerFunctionality < 6 {
		return "", ErrAuthenticationPolicyPrerequisite
	}
	return "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services," + *root.ConfigurationNamingContext, nil
}

func InternalAuthenticationPolicyScope(root RootDSE, object Object) error {
	container, err := InternalAuthenticationPolicyContainer(root)
	if err != nil {
		return err
	}
	parts, err := InternalSplitIdentityDN(object.DistinguishedName, ',')
	if err != nil || len(parts) < 2 ||
		!InternalSameAuthenticationDN(strings.Join(parts[1:], ","), container) {
		return ErrNotAuthenticationPolicy
	}
	classes, state := object.Attribute("objectClass")
	if state != AttributePresent ||
		!slices.ContainsFunc(
			classes,
			func(value []byte) bool { return strings.EqualFold(string(value), "msDS-AuthNPolicy") },
		) {
		return ErrNotAuthenticationPolicy
	}
	return nil
}

func InternalSameAuthenticationDN(a, b string) bool {
	left, err := InternalParseIdentityDN(a)
	if err != nil {
		return false
	}
	right, err := InternalParseIdentityDN(b)
	return err == nil && InternalSameIdentityDN(left, right)
}

func InternalDecodeAuthenticationPolicy(object Object) (AuthenticationPolicy, error) {
	policy := AuthenticationPolicy{DistinguishedName: object.DistinguishedName, Raw: object}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	policy.Name, policy.Description = d.InternalText("name"), d.InternalText("description")
	policy.Enforced = InternalDecodeScalar(&d, "msDS-AuthNPolicyEnforced", InternalParseLDAPBool)
	policy.UserAllowedNTLMNetworkAuthentication = InternalDecodeScalar(
		&d,
		"msDS-UserAllowedNTLMNetworkAuthentication",
		InternalParseLDAPBool,
	)
	policy.ServiceAllowedNTLMNetworkAuthentication = InternalDecodeScalar(
		&d,
		"msDS-ServiceAllowedNTLMNetworkAuthentication",
		InternalParseLDAPBool,
	)
	for name, target := range map[string]**Interval100ns{
		"msDS-UserTGTLifetime":     &policy.UserTGTLifetime,
		"msDS-ComputerTGTLifetime": &policy.ComputerTGTLifetime,
		"msDS-ServiceTGTLifetime":  &policy.ServiceTGTLifetime,
	} {
		*target = InternalDecodeScalar(
			&d,
			name,
			func(value string) (Interval100ns, error) { return NewRawValue([]byte(value)).Interval() },
		)
	}
	policy.RollingNTLMSecret = InternalDecodeScalar(
		&d,
		"msDS-StrongNTLMPolicy",
		func(value string) (StrongNTLMPolicy, error) {
			parsed, err := NewRawValue([]byte(value)).Flags32()
			return StrongNTLMPolicy(int32(parsed)), err
		},
	)
	for name, target := range map[string]**RawValue{
		"msDS-UserAllowedToAuthenticateFrom":    &policy.UserAllowedToAuthenticateFrom,
		"msDS-UserAllowedToAuthenticateTo":      &policy.UserAllowedToAuthenticateTo,
		"msDS-ComputerAllowedToAuthenticateTo":  &policy.ComputerAllowedToAuthenticateTo,
		"msDS-ServiceAllowedToAuthenticateFrom": &policy.ServiceAllowedToAuthenticateFrom,
		"msDS-ServiceAllowedToAuthenticateTo":   &policy.ServiceAllowedToAuthenticateTo,
	} {
		values := object.Values(name)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			d.InternalErrors = append(d.InternalErrors, err)
		} else {
			*target = &value
		}
	}
	if values := object.Values("objectGUID"); values.State == AttributePresent {
		value, err := values.Single()
		if err == nil {
			var guid GUID
			guid, err = value.GUID()
			if err == nil {
				policy.GUID = &guid
			}
		}
		d.InternalErrors = append(d.InternalErrors, err)
	}
	return policy, errors.Join(d.InternalErrors...)
}
