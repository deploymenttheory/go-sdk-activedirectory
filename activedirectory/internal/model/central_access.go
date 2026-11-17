package model

import (
	"crypto/rand"
	"errors"
	"slices"
	"strings"
)

var (
	ErrCentralAccess            = errors.New("invalid central access policy or rule operation")
	ErrCentralAccessMemberLimit = errors.New(
		"central access policy exceeds 127 observed member rules",
	)
	ErrCentralAccessReferences = errors.New("central access references are incomplete or changed")
)

const (
	CentralAccessPolicyMemberLimit = 127
	DefaultCentralAccessRuleACL    = "O:SYG:SYD:(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)"
	InternalCentralCurrent         = "msAuthz-EffectiveSecurityPolicy"
	InternalCentralProposed        = "msAuthz-ProposedSecurityPolicy"
	InternalCentralPrevious        = "msAuthz-LastEffectiveSecurityPolicy"
	InternalCentralCondition       = "msAuthz-ResourceCondition"
	InternalCentralPolicyID        = "msAuthz-CentralAccessPolicyID"
	InternalCentralMembers         = "msAuthz-MemberRulesInCentralAccessPolicy"
	InternalCentralMemberOf        = "msAuthz-MemberRulesInCentralAccessPolicyBL"
)

// Permission descriptors and resource expressions are separate Unicode LDAP
// strings. They are not nTSecurityDescriptor or binary authentication policies.
type CentralAccessRule struct {
	Raw                                                     Object
	GUID                                                    *GUID
	Name, Description                                       *string
	CurrentACL, ProposedACL, PreviousACL, ResourceCondition *string
	ProtectedFromAccidentalDeletion                         *bool
}
type CentralAccessPolicy struct {
	Raw                             Object
	GUID                            *GUID
	Name, Description               *string
	PolicyID                        *SID
	ProtectedFromAccidentalDeletion *bool
}
type CentralAccessReadOptions struct {
	ResolveIdentityOptions
	IncludeProtection bool
	References        CentralAccessReferenceLimits
}
type CentralAccessRuleResult struct {
	Rule        *CentralAccessRule
	Observation IdentityResult
	Policies    CentralAccessReferencesResult
	Protection  OUProtectionResult
}
type CentralAccessPolicyResult struct {
	Policy      *CentralAccessPolicy
	Observation IdentityResult
	Members     CentralAccessReferencesResult
	Protection  OUProtectionResult
}
type CentralAccessRulesResult struct {
	Rules       []CentralAccessRuleResult
	Observation SearchResult
}
type CentralAccessPoliciesResult struct {
	Policies    []CentralAccessPolicyResult
	Observation SearchResult
}

func InternalCentralAccessConfiguration(
	root RootDSE,
	config Config,
	partition string,
) (string, error) {
	if root.Capabilities().Type != DirectoryADDS {
		return "", ErrUnsupported
	}
	if root.ConfigurationNamingContext == nil {
		return "", ErrInvalidResult
	}
	configuration := *root.ConfigurationNamingContext
	if partition != "" && !InternalCentralSameDN(partition, configuration) {
		return "", ErrIdentityScope
	}
	if config.Endpoint.Port == 3268 || config.Endpoint.Port == 3269 {
		return "", ErrObjectWriteTarget
	}
	return configuration, nil
}

func InternalCentralSameDN(a, b string) bool {
	left, e := InternalParseIdentityDN(a)
	right, re := InternalParseIdentityDN(b)
	return e == nil && re == nil && InternalSameIdentityDN(left, right)
}

func InternalCentralAccessParent(configuration string, policy bool) string {
	container := "Central Access Rules"
	if policy {
		container = "Central Access Policies"
	}
	return "CN=" + container + ",CN=Claims Configuration,CN=Services," + configuration
}

func InternalCentralAccessClass(policy bool) string {
	if policy {
		return "msAuthz-CentralAccessPolicy"
	}
	return "msAuthz-CentralAccessRule"
}

func InternalCentralAccessClassCheck(object Object, class string) error {
	values := object.Values("objectClass")
	if values.State != AttributePresent {
		return ErrAttributeUnavailable
	}
	for _, value := range values.Values {
		text, err := value.Text()
		if err != nil {
			return err
		}
		if strings.EqualFold(text, class) {
			return nil
		}
	}
	return ErrCentralAccess
}

func InternalCentralAccessLocation(object Object, configuration string, policy bool) error {
	if err := InternalCentralAccessClassCheck(
		object,
		InternalCentralAccessClass(policy),
	); err != nil {
		return err
	}
	parent, err := InternalParentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	if !InternalCentralSameDN(parent, InternalCentralAccessParent(configuration, policy)) {
		return ErrIdentityScope
	}
	return nil
}

func InternalCentralAccessGUID(object Object) (GUID, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, err
	}
	return value.GUID()
}

func InternalCentralAccessProperties(extra []string, policy bool) []string {
	properties := append(
		slices.Clone(extra),
		"objectGUID",
		"uSNChanged",
		"objectClass",
		"name",
		"description",
	)
	if policy {
		return append(properties, InternalCentralPolicyID)
	}
	return append(
		properties,
		InternalCentralCurrent,
		InternalCentralProposed,
		InternalCentralPrevious,
		InternalCentralCondition,
	)
}

func InternalDecodeCentralAccessRule(object Object) (CentralAccessRule, error) {
	result := CentralAccessRule{Raw: object}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.Name = d.InternalText("name")
	result.Description = d.InternalText("description")
	result.CurrentACL = d.InternalText(InternalCentralCurrent)
	result.ProposedACL = d.InternalText(InternalCentralProposed)
	result.PreviousACL = d.InternalText(InternalCentralPrevious)
	result.ResourceCondition = d.InternalText(InternalCentralCondition)
	guid, err := InternalCentralAccessGUID(object)
	if err == nil {
		result.GUID = &guid
	}
	return result, errors.Join(
		err,
		InternalCentralAccessClassCheck(object, InternalCentralAccessClass(false)),
		errors.Join(d.InternalErrors...),
	)
}

func InternalValidCentralAccessPolicyID(sid SID) bool {
	raw := sid.Bytes()
	return len(raw) == 24 && raw[0] == 1 && raw[1] == 4 && raw[2] == 0 && raw[3] == 0 &&
		raw[4] == 0 &&
		raw[5] == 0 &&
		raw[6] == 0 &&
		raw[7] == 17
}

func InternalNewCentralAccessPolicyID() (SID, error) {
	// Scoped policy IDs use authority 17 and a 128-bit unique identifier. Keep
	// the generated ID in the result even when the following Add is uncertain.
	raw := make([]byte, 24)
	raw[0], raw[1], raw[7] = 1, 4, 17
	if _, err := rand.Read(raw[8:]); err != nil {
		return SID{}, err
	}
	return SIDFromBytes(raw)
}

func InternalDecodeCentralAccessPolicy(object Object) (CentralAccessPolicy, error) {
	result := CentralAccessPolicy{Raw: object}
	d := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	result.Name = d.InternalText("name")
	result.Description = d.InternalText("description")
	guid, err := InternalCentralAccessGUID(object)
	if err == nil {
		result.GUID = &guid
	}
	if _, state := object.Attribute(InternalCentralPolicyID); state == AttributePresent {
		value, e := object.Values(InternalCentralPolicyID).Single()
		if e == nil {
			sid, se := value.SID()
			e = se
			if e == nil && !InternalValidCentralAccessPolicyID(sid) {
				e = ErrInvalidValue
			}
			if e == nil {
				result.PolicyID = &sid
			}
		}
		err = errors.Join(err, e)
	}
	return result, errors.Join(
		err,
		InternalCentralAccessClassCheck(object, InternalCentralAccessClass(true)),
		errors.Join(d.InternalErrors...),
	)
}

func InternalCentralAccessIdentity(identity Identity, options ResolveIdentityOptions) error {
	if options.Target != IdentityTargetObject {
		return ErrUnsupportedIdentity
	}
	return InternalValidateIdentityOperation(identity, options)
}
