package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
)

var (
	ErrInvalidFineGrainedPolicy = errors.New("invalid fine-grained password policy")
	ErrFineGrainedPolicyTarget  = errors.New("fine-grained password policy requires an AD DS domain at Windows Server 2008 functional level or later")
	ErrFineGrainedPolicySubject = errors.New("password policy subject must be a user or global security group in the policy domain")
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

func fineGrainedPolicyProperties(extra []string) []string {
	return append(slices.Clone(extra), "objectClass", "objectGUID", "name", "description", "displayName", "msDS-PasswordSettingsPrecedence", "msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled", "msDS-PasswordHistoryLength", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold", "msDS-MinimumPasswordAge", "msDS-MaximumPasswordAge", "msDS-LockoutDuration", "msDS-LockoutObservationWindow", "msDS-PSOAppliesTo")
}

func fineGrainedPolicyClass(object Object) error {
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

func decodeFineGrainedPolicy(object Object) (FineGrainedPasswordPolicy, error) {
	policy := FineGrainedPasswordPolicy{DistinguishedName: object.DistinguishedName, Raw: object, AppliesTo: object.Values("msDS-PSOAppliesTo")}
	if err := fineGrainedPolicyClass(object); err != nil {
		return policy, err
	}
	d := rootDSEDecoder{attributes: object.Attributes}
	policy.Name, policy.Description, policy.DisplayName = d.text("name"), d.text("description"), d.text("displayName")
	if values, state := object.Attribute("objectGUID"); state == AttributePresent {
		if len(values) != 1 {
			d.errors = append(d.errors, ErrInvalidResult)
		} else {
			guid, err := GUIDFromBytes(values[0])
			if err != nil {
				d.errors = append(d.errors, err)
			} else {
				policy.GUID = &guid
			}
		}
	}
	policy.Settings.Precedence = decodeScalar(&d, "msDS-PasswordSettingsPrecedence", func(value string) (int32, error) { n, err := strconv.ParseInt(value, 10, 32); return int32(n), err })
	policy.Settings.ComplexityEnabled = decodeScalar(&d, "msDS-PasswordComplexityEnabled", parseLDAPBool)
	policy.Settings.ReversibleEncryptionEnabled = decodeScalar(&d, "msDS-PasswordReversibleEncryptionEnabled", parseLDAPBool)
	for _, field := range []struct {
		name  string
		value **uint16
	}{{"msDS-PasswordHistoryLength", &policy.Settings.PasswordHistoryCount}, {"msDS-MinimumPasswordLength", &policy.Settings.MinPasswordLength}, {"msDS-LockoutThreshold", &policy.Settings.LockoutThreshold}} {
		*field.value = decodeScalar(&d, field.name, func(value string) (uint16, error) { n, err := strconv.ParseUint(value, 10, 16); return uint16(n), err })
	}
	for _, field := range []struct {
		name  string
		value **PolicyInterval
	}{{"msDS-MinimumPasswordAge", &policy.Settings.MinPasswordAge}, {"msDS-MaximumPasswordAge", &policy.Settings.MaxPasswordAge}, {"msDS-LockoutDuration", &policy.Settings.LockoutDuration}, {"msDS-LockoutObservationWindow", &policy.Settings.LockoutObservationWindow}} {
		*field.value = decodeScalar(&d, field.name, parsePolicyInterval)
	}
	return policy, errors.Join(d.errors...)
}

func fineGrainedPolicyDomain(root RootDSE, config Config, partition string) (string, error) {
	if root.Capabilities().Type != DirectoryADDS || config.Endpoint.Port == 3268 || config.Endpoint.Port == 3269 {
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
	want, err := parseIdentityDN(*root.DefaultNamingContext)
	if err != nil {
		return "", err
	}
	actual, err := parseIdentityDN(partition)
	if err != nil || !sameIdentityDN(want, actual) {
		return "", ErrFineGrainedPolicyTarget
	}
	return *root.DefaultNamingContext, nil
}

func fineGrainedPolicyContainer(domain string) string {
	return "CN=Password Settings Container,CN=System," + domain
}

func fineGrainedPolicyLocation(object Object, domain string) error {
	dn, err := parseIdentityDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	parent, err := parseIdentityDN(fineGrainedPolicyContainer(domain))
	if err != nil {
		return err
	}
	if len(dn) != len(parent)+1 || !sameIdentityDN(dn[1:], parent) {
		return ErrFineGrainedPolicyTarget
	}
	return fineGrainedPolicyClass(object)
}

// FineGrainedPasswordPolicy resolves a PSO by explicit DN/GUID. Policy names
// are not guessed as SAM identities; search supports a typed name filter.
func (c *Client) FineGrainedPasswordPolicy(ctx context.Context, identity Identity, options ResolveIdentityOptions) (FineGrainedPasswordPolicyResult, error) {
	var result FineGrainedPasswordPolicyResult
	if options.Target != IdentityTargetObject || (identity.Form() != IdentityFormDN && identity.Form() != IdentityFormGUID) {
		return result, ErrUnsupportedIdentity
	}
	options.Properties = fineGrainedPolicyProperties(options.Properties)
	if err := validateIdentityOperation(identity, options); err != nil {
		return result, err
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		domain, err := fineGrainedPolicyDomain(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		options.Partition = domain
		result.Observation, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, options)
		if err != nil {
			return err
		}
		if err := fineGrainedPolicyLocation(*result.Observation.Object, domain); err != nil {
			return err
		}
		policy, err := decodeFineGrainedPolicy(*result.Observation.Object)
		result.Policy = &policy
		return err
	})
	return result, err
}

// FineGrainedPasswordPolicies searches only the domain's Password Settings
// Container. Scope is fixed to its direct children; paging/limits and raw or
// typed filters use the existing SearchOptions contract.
func (c *Client) FineGrainedPasswordPolicies(ctx context.Context, options SearchOptions) (FineGrainedPasswordPoliciesResult, error) {
	var result FineGrainedPasswordPoliciesResult
	if err := options.Validate(); err != nil {
		return result, err
	}
	options.Properties = fineGrainedPolicyProperties(options.Properties)
	if !options.TypedFilter.unset() {
		options.TypedFilter = FilterAnd(FilterEqual("objectClass", FilterText("msDS-PasswordSettings")), options.TypedFilter)
	} else if options.Filter == "" {
		options.Filter = "(objectClass=msDS-PasswordSettings)"
	} else {
		options.Filter = "(&(objectClass=msDS-PasswordSettings)" + options.Filter + ")"
	}
	err := c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		domain, err := fineGrainedPolicyDomain(root, c.config, "")
		if err != nil {
			return err
		}
		container := fineGrainedPolicyContainer(domain)
		if options.Base != "" {
			actual, e := parseIdentityDN(options.Base)
			want, _ := parseIdentityDN(container)
			if e != nil || !sameIdentityDN(actual, want) {
				return ErrFineGrainedPolicyTarget
			}
		}
		options.Base, options.Scope = container, ScopeOneLevel
		result.Observation, err = searchIdentitySession(ctx, c.session, options)
		for _, object := range result.Observation.Objects {
			policy, decodeErr := decodeFineGrainedPolicy(object)
			result.Policies = append(result.Policies, policy)
			err = errors.Join(err, decodeErr, fineGrainedPolicyLocation(object, domain))
		}
		if err != nil {
			result.Observation.Complete = false
		}
		return err
	})
	return result, err
}
