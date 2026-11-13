package activedirectory

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
)

var (
	ErrCentralAccess            = errors.New("invalid central access policy or rule operation")
	ErrCentralAccessMemberLimit = errors.New("central access policy exceeds 127 observed member rules")
	ErrCentralAccessReferences  = errors.New("central access references are incomplete or changed")
)

const CentralAccessPolicyMemberLimit = 127
const DefaultCentralAccessRuleACL = "O:SYG:SYD:(A;;FA;;;OW)(A;;FA;;;BA)(A;;FA;;;SY)"
const centralCurrent = "msAuthz-EffectiveSecurityPolicy"
const centralProposed = "msAuthz-ProposedSecurityPolicy"
const centralPrevious = "msAuthz-LastEffectiveSecurityPolicy"
const centralCondition = "msAuthz-ResourceCondition"
const centralPolicyID = "msAuthz-CentralAccessPolicyID"
const centralMembers = "msAuthz-MemberRulesInCentralAccessPolicy"
const centralMemberOf = "msAuthz-MemberRulesInCentralAccessPolicyBL"

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

func centralAccessConfiguration(root RootDSE, config Config, partition string) (string, error) {
	if root.Capabilities().Type != DirectoryADDS {
		return "", ErrUnsupported
	}
	if root.ConfigurationNamingContext == nil {
		return "", ErrInvalidResult
	}
	configuration := *root.ConfigurationNamingContext
	if partition != "" && !centralSameDN(partition, configuration) {
		return "", ErrIdentityScope
	}
	if config.Endpoint.Port == 3268 || config.Endpoint.Port == 3269 {
		return "", ErrObjectWriteTarget
	}
	return configuration, nil
}
func centralSameDN(a, b string) bool {
	left, e := parseIdentityDN(a)
	right, re := parseIdentityDN(b)
	return e == nil && re == nil && sameIdentityDN(left, right)
}
func centralAccessParent(configuration string, policy bool) string {
	container := "Central Access Rules"
	if policy {
		container = "Central Access Policies"
	}
	return "CN=" + container + ",CN=Claims Configuration,CN=Services," + configuration
}
func centralAccessClass(policy bool) string {
	if policy {
		return "msAuthz-CentralAccessPolicy"
	}
	return "msAuthz-CentralAccessRule"
}
func centralAccessClassCheck(object Object, class string) error {
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
func centralAccessLocation(object Object, configuration string, policy bool) error {
	if err := centralAccessClassCheck(object, centralAccessClass(policy)); err != nil {
		return err
	}
	parent, err := parentDirectoryDN(object.DistinguishedName)
	if err != nil {
		return err
	}
	if !centralSameDN(parent, centralAccessParent(configuration, policy)) {
		return ErrIdentityScope
	}
	return nil
}
func centralAccessGUID(object Object) (GUID, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, err
	}
	return value.GUID()
}
func centralAccessProperties(extra []string, policy bool) []string {
	properties := append(slices.Clone(extra), "objectGUID", "uSNChanged", "objectClass", "name", "description")
	if policy {
		return append(properties, centralPolicyID)
	}
	return append(properties, centralCurrent, centralProposed, centralPrevious, centralCondition)
}
func decodeCentralAccessRule(object Object) (CentralAccessRule, error) {
	result := CentralAccessRule{Raw: object}
	d := rootDSEDecoder{attributes: object.Attributes}
	result.Name = d.text("name")
	result.Description = d.text("description")
	result.CurrentACL = d.text(centralCurrent)
	result.ProposedACL = d.text(centralProposed)
	result.PreviousACL = d.text(centralPrevious)
	result.ResourceCondition = d.text(centralCondition)
	guid, err := centralAccessGUID(object)
	if err == nil {
		result.GUID = &guid
	}
	return result, errors.Join(err, centralAccessClassCheck(object, centralAccessClass(false)), errors.Join(d.errors...))
}
func validCentralAccessPolicyID(sid SID) bool {
	raw := sid.Bytes()
	return len(raw) == 24 && raw[0] == 1 && raw[1] == 4 && raw[2] == 0 && raw[3] == 0 && raw[4] == 0 && raw[5] == 0 && raw[6] == 0 && raw[7] == 17
}
func newCentralAccessPolicyID() (SID, error) {
	// Scoped policy IDs use authority 17 and a 128-bit unique identifier. Keep
	// the generated ID in the result even when the following Add is uncertain.
	raw := make([]byte, 24)
	raw[0], raw[1], raw[7] = 1, 4, 17
	if _, err := rand.Read(raw[8:]); err != nil {
		return SID{}, err
	}
	return SIDFromBytes(raw)
}
func decodeCentralAccessPolicy(object Object) (CentralAccessPolicy, error) {
	result := CentralAccessPolicy{Raw: object}
	d := rootDSEDecoder{attributes: object.Attributes}
	result.Name = d.text("name")
	result.Description = d.text("description")
	guid, err := centralAccessGUID(object)
	if err == nil {
		result.GUID = &guid
	}
	if _, state := object.Attribute(centralPolicyID); state == AttributePresent {
		value, e := object.Values(centralPolicyID).Single()
		if e == nil {
			sid, se := value.SID()
			e = se
			if e == nil && !validCentralAccessPolicyID(sid) {
				e = ErrInvalidValue
			}
			if e == nil {
				result.PolicyID = &sid
			}
		}
		err = errors.Join(err, e)
	}
	return result, errors.Join(err, centralAccessClassCheck(object, centralAccessClass(true)), errors.Join(d.errors...))
}
func centralAccessIdentity(identity Identity, options ResolveIdentityOptions) error {
	if options.Target != IdentityTargetObject {
		return ErrUnsupportedIdentity
	}
	return validateIdentityOperation(identity, options)
}
func (c *Client) readCentralAccess(ctx context.Context, identity Identity, options CentralAccessReadOptions, policy bool) (IdentityResult, CentralAccessReferencesResult, OUProtectionResult, error) {
	var observed IdentityResult
	var references CentralAccessReferencesResult
	var protection OUProtectionResult
	if err := centralAccessIdentity(identity, options.ResolveIdentityOptions); err != nil {
		return observed, references, protection, err
	}
	limits, err := normalizeCentralAccessLimits(options.References)
	if err != nil {
		return observed, references, protection, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err := centralAccessConfiguration(root, c.config, options.Partition)
		if err != nil {
			return err
		}
		resolve := options.ResolveIdentityOptions
		resolve.Partition = configuration
		resolve.Properties = centralAccessProperties(resolve.Properties, policy)
		observed, err = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if err != nil {
			return err
		}
		if err := centralAccessLocation(*observed.Object, configuration, policy); err != nil {
			return err
		}
		attribute := centralMemberOf
		if policy {
			attribute = centralMembers
		}
		references, err = readCentralAccessReferences(ctx, c.session, *observed.Object, attribute, limits)
		if options.IncludeProtection {
			guid, e := centralAccessGUID(*observed.Object)
			if e == nil {
				protection, e = readOUProtection(ctx, c.session, root, c.config, OrganizationalUnit{DistinguishedName: observed.Object.DistinguishedName, GUID: &guid}, configuration)
			}
			err = errors.Join(err, e)
		}
		return err
	})
	return observed, references, protection, err
}
func (c *Client) CentralAccessRule(ctx context.Context, identity Identity, options CentralAccessReadOptions) (CentralAccessRuleResult, error) {
	var result CentralAccessRuleResult
	var err error
	result.Observation, result.Policies, result.Protection, err = c.readCentralAccess(ctx, identity, options, false)
	if result.Observation.Object != nil {
		value, e := decodeCentralAccessRule(*result.Observation.Object)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Rule = &value
		err = errors.Join(err, e)
	}
	return result, err
}
func (c *Client) CentralAccessPolicy(ctx context.Context, identity Identity, options CentralAccessReadOptions) (CentralAccessPolicyResult, error) {
	var result CentralAccessPolicyResult
	var err error
	result.Observation, result.Members, result.Protection, err = c.readCentralAccess(ctx, identity, options, true)
	if result.Observation.Object != nil {
		value, e := decodeCentralAccessPolicy(*result.Observation.Object)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Policy = &value
		err = errors.Join(err, e)
	}
	return result, err
}
func (c *Client) searchCentralAccess(ctx context.Context, options SearchOptions, limits CentralAccessReferenceLimits, policy bool) (SearchResult, []CentralAccessReferencesResult, error) {
	var result SearchResult
	var references []CentralAccessReferencesResult
	query, err := options.normalized()
	if err != nil {
		return result, references, err
	}
	limits, err = normalizeCentralAccessLimits(limits)
	if err != nil {
		return result, references, err
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, err := readIdentityRoot(ctx, c.session)
		if err != nil {
			return err
		}
		configuration, err := centralAccessConfiguration(root, c.config, "")
		if err != nil {
			return err
		}
		parent := centralAccessParent(configuration, policy)
		if query.Base != "" && !centralSameDN(query.Base, parent) {
			return ErrIdentityScope
		}
		query.Base = parent
		query.Scope = ScopeOneLevel
		query.Filter = "(&(objectClass=" + centralAccessClass(policy) + ")" + query.Filter + ")"
		query.Properties = centralAccessProperties(options.Properties, policy)
		result, err = searchIdentitySession(ctx, c.session, query)
		attribute := centralMemberOf
		if policy {
			attribute = centralMembers
		}
		for _, object := range result.Objects {
			var refs CentralAccessReferencesResult
			e := centralAccessLocation(object, configuration, policy)
			if e == nil {
				refs, e = readCentralAccessReferences(ctx, c.session, object, attribute, limits)
			}
			references = append(references, refs)
			err = errors.Join(err, e)
		}
		return err
	})
	if err != nil {
		result.Complete = false
	}
	return result, references, err
}
func (c *Client) CentralAccessRules(ctx context.Context, options SearchOptions, limits CentralAccessReferenceLimits) (CentralAccessRulesResult, error) {
	var result CentralAccessRulesResult
	observed, references, err := c.searchCentralAccess(ctx, options, limits, false)
	result.Observation = observed
	for i, object := range observed.Objects {
		rule, e := decodeCentralAccessRule(object)
		result.Rules = append(result.Rules, CentralAccessRuleResult{Rule: &rule, Observation: IdentityResult{Object: &object, Complete: true}, Policies: references[i]})
		err = errors.Join(err, e)
	}
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
func (c *Client) CentralAccessPolicies(ctx context.Context, options SearchOptions, limits CentralAccessReferenceLimits) (CentralAccessPoliciesResult, error) {
	var result CentralAccessPoliciesResult
	observed, references, err := c.searchCentralAccess(ctx, options, limits, true)
	result.Observation = observed
	for i, object := range observed.Objects {
		policy, e := decodeCentralAccessPolicy(object)
		result.Policies = append(result.Policies, CentralAccessPolicyResult{Policy: &policy, Observation: IdentityResult{Object: &object, Complete: true}, Members: references[i]})
		err = errors.Join(err, e)
	}
	if err != nil {
		result.Observation.Complete = false
	}
	return result, err
}
