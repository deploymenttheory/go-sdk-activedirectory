package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"
)

var (
	ErrInvalidAuthenticationPolicy      = errors.New("invalid authentication policy request")
	ErrNotAuthenticationPolicy          = errors.New("object is not an authentication policy in this forest's policy container")
	ErrAuthenticationPolicyPrerequisite = errors.New("authentication policy requires AD DS and supported schema/domain/controller functionality")
	ErrAuthenticationPolicyDescriptor   = errors.New("descriptor is not suitable for authentication-policy control-access checks")
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

func authenticationPolicyProperties(extra []string) []string {
	properties := slices.DeleteFunc(slices.Clone(extra), func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") })
	return append(properties, "objectGUID", "objectClass", "name", "description", "msDS-AuthNPolicyEnforced", "msDS-UserTGTLifetime", "msDS-ComputerTGTLifetime", "msDS-ServiceTGTLifetime", "msDS-UserAllowedToAuthenticateFrom", "msDS-UserAllowedToAuthenticateTo", "msDS-ComputerAllowedToAuthenticateTo", "msDS-ServiceAllowedToAuthenticateFrom", "msDS-ServiceAllowedToAuthenticateTo", "msDS-UserAllowedNTLMNetworkAuthentication", "msDS-ServiceAllowedNTLMNetworkAuthentication", "msDS-StrongNTLMPolicy")
}

func authenticationPolicyContainer(root RootDSE) (string, error) {
	if err := root.Capabilities().RequireADDS("AuthenticationPolicy"); err != nil {
		return "", err
	}
	if root.ConfigurationNamingContext == nil || root.DomainControllerFunctionality == nil || *root.DomainControllerFunctionality < 6 {
		return "", ErrAuthenticationPolicyPrerequisite
	}
	return "CN=AuthN Policies,CN=AuthN Policy Configuration,CN=Services," + *root.ConfigurationNamingContext, nil
}

func authenticationPolicyScope(root RootDSE, object Object) error {
	container, err := authenticationPolicyContainer(root)
	if err != nil {
		return err
	}
	parts, err := splitIdentityDN(object.DistinguishedName, ',')
	if err != nil || len(parts) < 2 || !sameAuthenticationDN(strings.Join(parts[1:], ","), container) {
		return ErrNotAuthenticationPolicy
	}
	classes, state := object.Attribute("objectClass")
	if state != AttributePresent || !slices.ContainsFunc(classes, func(value []byte) bool { return strings.EqualFold(string(value), "msDS-AuthNPolicy") }) {
		return ErrNotAuthenticationPolicy
	}
	return nil
}

func sameAuthenticationDN(a, b string) bool {
	left, err := parseIdentityDN(a)
	if err != nil {
		return false
	}
	right, err := parseIdentityDN(b)
	return err == nil && sameIdentityDN(left, right)
}

func decodeAuthenticationPolicy(object Object) (AuthenticationPolicy, error) {
	policy := AuthenticationPolicy{DistinguishedName: object.DistinguishedName, Raw: object}
	d := rootDSEDecoder{attributes: object.Attributes}
	policy.Name, policy.Description = d.text("name"), d.text("description")
	policy.Enforced = decodeScalar(&d, "msDS-AuthNPolicyEnforced", parseLDAPBool)
	policy.UserAllowedNTLMNetworkAuthentication = decodeScalar(&d, "msDS-UserAllowedNTLMNetworkAuthentication", parseLDAPBool)
	policy.ServiceAllowedNTLMNetworkAuthentication = decodeScalar(&d, "msDS-ServiceAllowedNTLMNetworkAuthentication", parseLDAPBool)
	for name, target := range map[string]**Interval100ns{"msDS-UserTGTLifetime": &policy.UserTGTLifetime, "msDS-ComputerTGTLifetime": &policy.ComputerTGTLifetime, "msDS-ServiceTGTLifetime": &policy.ServiceTGTLifetime} {
		*target = decodeScalar(&d, name, func(value string) (Interval100ns, error) { return NewRawValue([]byte(value)).Interval() })
	}
	policy.RollingNTLMSecret = decodeScalar(&d, "msDS-StrongNTLMPolicy", func(value string) (StrongNTLMPolicy, error) {
		parsed, err := NewRawValue([]byte(value)).Flags32()
		return StrongNTLMPolicy(int32(parsed)), err
	})
	for name, target := range map[string]**RawValue{"msDS-UserAllowedToAuthenticateFrom": &policy.UserAllowedToAuthenticateFrom, "msDS-UserAllowedToAuthenticateTo": &policy.UserAllowedToAuthenticateTo, "msDS-ComputerAllowedToAuthenticateTo": &policy.ComputerAllowedToAuthenticateTo, "msDS-ServiceAllowedToAuthenticateFrom": &policy.ServiceAllowedToAuthenticateFrom, "msDS-ServiceAllowedToAuthenticateTo": &policy.ServiceAllowedToAuthenticateTo} {
		values := object.Values(name)
		if values.State == AttributeAbsent || values.State == AttributeUnloaded {
			continue
		}
		value, err := values.Single()
		if err != nil {
			d.errors = append(d.errors, err)
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
		d.errors = append(d.errors, err)
	}
	return policy, errors.Join(d.errors...)
}

// AuthenticationPolicy resolves an explicit DN/GUID inside this forest's policy
// container. Missing values remain nil, not inferred defaults. Protection is
// read only when requested in Properties, using the existing ACL observation.
func (c *Client) AuthenticationPolicy(ctx context.Context, identity Identity, options ResolveIdentityOptions) (AuthenticationPolicyResult, error) {
	var result AuthenticationPolicyResult
	if options.Target != IdentityTargetObject {
		return result, ErrUnsupportedIdentity
	}
	if err := validateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	protection := slices.ContainsFunc(options.Properties, func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") })
	options.Properties = authenticationPolicyProperties(options.Properties)
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		if _, err := authenticationPolicyContainer(root); err != nil {
			return err
		}
		if options.Partition != "" && !sameAuthenticationDN(options.Partition, *root.ConfigurationNamingContext) {
			return ErrIdentityScope
		}
		options.Partition = *root.ConfigurationNamingContext
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if err != nil {
			return err
		}
		if err := authenticationPolicyScope(root, *result.Observation.Object); err != nil {
			return err
		}
		policy, err := decodeAuthenticationPolicy(*result.Observation.Object)
		result.Policy = &policy
		if err != nil || !protection {
			return err
		}
		result.Protection, err = readOUProtection(ctx, c.session, root, c.config, OrganizationalUnit{DistinguishedName: policy.DistinguishedName, GUID: policy.GUID}, options.Partition)
		result.Policy.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		return err
	})
	return result, err
}

// AuthenticationPolicies intersects the caller's shared typed/LDAP filter with
// msDS-AuthNPolicy and defaults to a one-level search of the policy container.
// A Name equality filter supplies explicit name lookup without guessing a DN.
func (c *Client) AuthenticationPolicies(ctx context.Context, options SearchOptions) (AuthenticationPoliciesResult, error) {
	var result AuthenticationPoliciesResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	protection := slices.ContainsFunc(options.Properties, func(name string) bool { return strings.EqualFold(name, "ProtectedFromAccidentalDeletion") })
	options.Properties = authenticationPolicyProperties(options.Properties)
	if !options.TypedFilter.unset() {
		options.TypedFilter = FilterAnd(FilterEqual("objectClass", FilterText("msDS-AuthNPolicy")), options.TypedFilter)
	} else if options.Filter == "" {
		options.Filter = "(objectClass=msDS-AuthNPolicy)"
	} else {
		options.Filter = "(&(objectClass=msDS-AuthNPolicy)" + options.Filter + ")"
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		container, err := authenticationPolicyContainer(root)
		if err != nil {
			return err
		}
		if options.Base == "" {
			options.Base, options.Scope = container, ScopeOneLevel
		}
		base, err := parseIdentityDN(options.Base)
		if err != nil {
			return err
		}
		parent, _ := parseIdentityDN(container)
		if !identityWithin(base, parent) {
			return ErrIdentityScope
		}
		result.Observation, err = searchIdentitySession(ctx, c.session, options)
		searchErr := err
		for _, raw := range result.Observation.Objects {
			policy, decodeErr := decodeAuthenticationPolicy(raw)
			decodeErr = errors.Join(decodeErr, authenticationPolicyScope(root, raw))
			if protection && decodeErr == nil && searchErr == nil {
				observed, readErr := readOUProtection(ctx, c.session, root, c.config, OrganizationalUnit{DistinguishedName: policy.DistinguishedName, GUID: policy.GUID}, *root.ConfigurationNamingContext)
				policy.ProtectedFromAccidentalDeletion = observed.ProtectedFromAccidentalDeletion
				result.Protection = append(result.Protection, observed)
				decodeErr = errors.Join(decodeErr, readErr)
			}
			result.Policies = append(result.Policies, policy)
			err = errors.Join(err, decodeErr)
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}
