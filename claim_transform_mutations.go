package activedirectory

import (
	"context"
	"errors"
	"strings"
)

// CreateClaimTransformPolicyRequest creates one policy under the configuration
// partition's Claims Transformation Policies container.
type CreateClaimTransformPolicyRequest struct {
	Name        string
	Description *string
	// Rules selects the stored rule form. The zero value creates a policy with
	// no rules rather than defaulting to allow or deny.
	Rules                           ClaimTransformRuleSet
	ProtectedFromAccidentalDeletion *bool
	// Attributes carries additional raw attributes. Managed attributes are
	// rejected rather than merged.
	Attributes map[string][]RawValue
	Options    ObjectMutationOptions
}

// UpdateClaimTransformPolicyRequest changes one policy. Nil and zero fields are
// left alone; ClearRules removes the rules attribute and conflicts with Rules.
type UpdateClaimTransformPolicyRequest struct {
	Identity                        Identity
	Description                     *string
	ClearDescription                bool
	Rules                           ClaimTransformRuleSet
	ClearRules                      bool
	ProtectedFromAccidentalDeletion *bool
	Changes                         []AttributeChange
	Options                         ObjectMutationOptions
}

type ClaimTransformPolicyMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	Policy     *ClaimTransformPolicy
}

// claimTransformManaged attributes are written only from typed fields. A raw
// change naming one would bypass rule validation and the CDATA envelope.
var claimTransformManaged = []string{
	"cn", "name", claimTransformRules, claimTransformCompiled, "nTSecurityDescriptor",
}

func claimTransformRawChanges(changes []AttributeChange) error {
	for _, change := range changes {
		for _, managed := range claimTransformManaged {
			if strings.EqualFold(change.Attribute, managed) {
				return ErrClaimTransformPolicy
			}
		}
	}
	return nil
}

func claimTransformRawAttributes(attributes map[string][]RawValue) error {
	for name := range attributes {
		for _, managed := range claimTransformManaged {
			if strings.EqualFold(name, managed) {
				return ErrClaimTransformPolicy
			}
		}
	}
	return nil
}

func claimTransformProject(result ClaimTransformPolicyMutationResult, err error) (ClaimTransformPolicyMutationResult, error) {
	if result.Mutation.After != nil {
		value, decodeErr := decodeClaimTransformPolicy(*result.Mutation.After)
		value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
		result.Policy = &value
		err = errors.Join(err, decodeErr)
	}
	return result, err
}

// CreateClaimTransformPolicy creates one policy. The rules are rendered and
// validated before anything is submitted.
func (c *Client) CreateClaimTransformPolicy(ctx context.Context, request CreateClaimTransformPolicyRequest) (ClaimTransformPolicyMutationResult, error) {
	var result ClaimTransformPolicyMutationResult
	if request.Name == "" || !validDirectoryText(request.Name) {
		return result, ErrInvalidObjectMutation
	}
	if request.Description != nil && !validDirectoryText(*request.Description) {
		return result, ErrInvalidObjectMutation
	}
	if request.Options.ExpectedVersion != nil {
		return result, ErrObjectControlUnsupported
	}
	if err := claimTransformRawAttributes(request.Attributes); err != nil {
		return result, err
	}
	stored, present, err := request.Rules.render()
	if err != nil {
		return result, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		return centralAccessProtectionCapability(c.session, root, request.ProtectedFromAccidentalDeletion)
	})
	if err != nil {
		return result, err
	}
	attributes := map[string][]RawValue{}
	for name, values := range request.Attributes {
		attributes[name] = values
	}
	if request.Description != nil {
		attributes["description"] = []RawValue{NewRawValue([]byte(*request.Description))}
	}
	if present {
		attributes[claimTransformRules] = []RawValue{NewRawValue([]byte(stored))}
	}
	parent, _ := IdentityByDN(claimTransformParent(options.Partition))
	options.Properties = claimTransformProperties(options.Properties)
	result.Mutation, err = c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: claimTransformClass, Name: request.Name, Attributes: attributes, Options: options})
	if err != nil {
		return claimTransformProject(result, err)
	}
	if request.ProtectedFromAccidentalDeletion != nil {
		protection, protectErr := c.setCentralAccessProtection(ctx, objectGUIDIdentity(*result.Mutation.TargetGUID), *request.ProtectedFromAccidentalDeletion, ObjectMutationOptions{Partition: options.Partition}, false)
		result.Protection = protection
		err = protectErr
	}
	return claimTransformProject(result, err)
}

func claimTransformUpdateChanges(request UpdateClaimTransformPolicyRequest) ([]AttributeChange, error) {
	if request.Description != nil && request.ClearDescription {
		return nil, ErrClaimTransformPolicy
	}
	if !request.Rules.empty() && request.ClearRules {
		return nil, ErrClaimTransformPolicy
	}
	if err := claimTransformRawChanges(request.Changes); err != nil {
		return nil, err
	}
	var changes []AttributeChange
	if request.Description != nil {
		if !validDirectoryText(*request.Description) {
			return nil, ErrInvalidObjectMutation
		}
		changes = append(changes, AttributeChange{Attribute: "description", Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*request.Description))}})
	}
	if request.ClearDescription {
		changes = append(changes, AttributeChange{Attribute: "description", Kind: AttributeClear})
	}
	stored, present, err := request.Rules.render()
	if err != nil {
		return nil, err
	}
	if present {
		changes = append(changes, AttributeChange{Attribute: claimTransformRules, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(stored))}})
	}
	if request.ClearRules {
		changes = append(changes, AttributeChange{Attribute: claimTransformRules, Kind: AttributeClear})
	}
	return append(changes, request.Changes...), nil
}

// UpdateClaimTransformPolicy changes one policy in a single modify.
func (c *Client) UpdateClaimTransformPolicy(ctx context.Context, request UpdateClaimTransformPolicyRequest) (ClaimTransformPolicyMutationResult, error) {
	var result ClaimTransformPolicyMutationResult
	changes, err := claimTransformUpdateChanges(request)
	if err != nil {
		return result, err
	}
	if err := validateObjectOptions(request.Identity, request.Options); err != nil {
		return result, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, request.Options)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = c.objectMutationIdentity(ctx, request.Identity, options, ResolveIdentityOptions{Properties: claimTransformProperties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := claimTransformLocation(*observed.Object, options.Partition); err != nil {
			return err
		}
		if err := centralAccessProtectionCapability(session, root, request.ProtectedFromAccidentalDeletion); err != nil {
			return err
		}
		mods, err := objectChanges(changes)
		if err != nil {
			return err
		}
		if len(mods) == 0 {
			if options.ExpectedVersion != nil && request.ProtectedFromAccidentalDeletion == nil {
				return ErrObjectControlUnsupported
			}
			mutation.After = mutation.Before
			mutation.ReadbackComplete = true
			mutation.Verified = true
		} else {
			controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
			if err != nil {
				return err
			}
			if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); err != nil {
				return err
			}
			readOptions := options
			readOptions.Properties = claimTransformProperties(options.Properties)
			if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, objectWriteProperties(readOptions, mods), false); err != nil {
				return err
			}
			if err := verifyObjectWrite(mutation, mods, ""); err != nil {
				return err
			}
		}
		if request.ProtectedFromAccidentalDeletion != nil {
			result.Protection.Object = *mutation
			return changeOUProtection(ctx, session, root, c.config, mutation, *request.ProtectedFromAccidentalDeletion, options, &result.Protection)
		}
		return nil
	})
	return claimTransformProject(result, err)
}

// DeleteClaimTransformPolicy removes one policy with a single native leaf
// delete. It never unprotects the object or clears trust links for the caller;
// a policy still linked from a trust is the directory's own referential
// concern and its refusal is surfaced unchanged.
func (c *Client) DeleteClaimTransformPolicy(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	if err := validateObjectOptions(identity, options); err != nil {
		return ObjectMutationResult{}, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, options)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	defer cancel()
	return c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{Properties: claimTransformProperties(options.Properties)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := claimTransformLocation(*observed.Object, options.Partition); err != nil {
			return err
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *result.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteDelete, dn: objectGUIDTarget(*result.TargetGUID), controls: controls}, false, result); err != nil {
			return err
		}
		return observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*result.TargetGUID), result, []string{"objectGUID"}, true)
	})
}

// ClaimTransformDirection names the trust attribute a link is written to.
//
// The reference exposes TrustRole instead. Which role maps to which direction
// has NOT been qualified against the reference — it needs a second forest with
// a trust, which the current lab does not have — and getting it backwards would
// apply a policy to the wrong direction of claims flow. The direction is
// therefore stated by the caller rather than derived from a role, so this SDK
// never guesses it. A TrustRole convenience can be added once observed.
type ClaimTransformDirection uint8

const (
	// ClaimTransformEgress writes msDS-EgressClaimsTransformationPolicy:
	// claims leaving this forest across the trust.
	ClaimTransformEgress ClaimTransformDirection = iota + 1
	// ClaimTransformIngress writes msDS-IngressClaimsTransformationPolicy:
	// claims entering this forest across the trust.
	ClaimTransformIngress
)

const (
	claimTransformEgressAttribute  = "msDS-EgressClaimsTransformationPolicy"
	claimTransformIngressAttribute = "msDS-IngressClaimsTransformationPolicy"
)

func (d ClaimTransformDirection) attribute() (string, error) {
	switch d {
	case ClaimTransformEgress:
		return claimTransformEgressAttribute, nil
	case ClaimTransformIngress:
		return claimTransformIngressAttribute, nil
	default:
		return "", ErrClaimTransformLink
	}
}

// ClaimTransformLinkRequest links or unlinks one policy on one trust.
type ClaimTransformLinkRequest struct {
	// Trust identifies a trustedDomain object. Its class and partition are
	// verified before any write.
	Trust Identity
	// Policy is the transformation policy to link. It is resolved and verified
	// to be a policy in the Claims Transformation Policies container, so a
	// link can never point at an arbitrary object. Ignored when clearing.
	Policy    Identity
	Direction ClaimTransformDirection
	Options   ObjectMutationOptions
}

type ClaimTransformLinkResult struct {
	Mutation ObjectMutationResult
	// PolicyObservation is the resolved policy the link was pointed at, or the
	// candidates seen while resolving it when that failed.
	PolicyObservation IdentityResult
	Attribute         string
}

// SetClaimTransformLink points one direction of a trust at a policy.
func (c *Client) SetClaimTransformLink(ctx context.Context, request ClaimTransformLinkRequest) (ClaimTransformLinkResult, error) {
	return c.changeClaimTransformLink(ctx, request, false)
}

// ClearClaimTransformLink removes the policy link from one direction of a
// trust. It does not delete the policy.
func (c *Client) ClearClaimTransformLink(ctx context.Context, request ClaimTransformLinkRequest) (ClaimTransformLinkResult, error) {
	return c.changeClaimTransformLink(ctx, request, true)
}

func (c *Client) changeClaimTransformLink(ctx context.Context, request ClaimTransformLinkRequest, clear bool) (ClaimTransformLinkResult, error) {
	var result ClaimTransformLinkResult
	attribute, err := request.Direction.attribute()
	if err != nil {
		return result, err
	}
	result.Attribute = attribute
	if err := validateObjectOptions(request.Trust, request.Options); err != nil {
		return result, err
	}
	if !clear && request.Policy.Form() == 0 {
		return result, errors.Join(ErrClaimTransformLink, ErrInvalidIdentity)
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	options := request.Options
	result.Mutation, err = c.objectMutationIdentity(bounded, request.Trust, options, ResolveIdentityOptions{Properties: []string{"objectGUID", "uSNChanged", "objectClass", "name", "trustPartner", attribute}}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		// The target must be a trust. A claim policy written onto an arbitrary
		// object would be silently meaningless.
		if err := centralAccessClassCheck(*observed.Object, "trustedDomain"); err != nil {
			return errors.Join(ErrClaimTransformLink, err)
		}
		mods := []ldapAttributeModification{{operation: 1, attribute: attribute}}
		if !clear {
			configuration, err := centralAccessConfiguration(root, c.config, "")
			if err != nil {
				return err
			}
			policy, err := resolveIdentitySession(ctx, session, c.config, root, request.Policy, ResolveIdentityOptions{Partition: configuration, Properties: claimTransformProperties(nil)})
			result.PolicyObservation = policy
			if err != nil {
				return err
			}
			if err := claimTransformLocation(*policy.Object, configuration); err != nil {
				return err
			}
			mods = []ldapAttributeModification{{operation: 2, attribute: attribute, values: [][]byte{[]byte(policy.Object.DistinguishedName)}}}
		}
		controls, err := objectWriteControls(root, c.config.Endpoint, options, *mutation.TargetGUID, false)
		if err != nil {
			return err
		}
		if err := submitObjectWrite(ctx, session, ldapWriteRequest{operation: ldapWriteModify, dn: objectGUIDTarget(*mutation.TargetGUID), modifications: mods, controls: controls}, false, mutation); err != nil {
			return err
		}
		if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, []string{"objectGUID", "uSNChanged", attribute}, false); err != nil {
			return err
		}
		// A clear of an already-absent value is not a failure, so the removal
		// is only verified when a value was written.
		if !clear {
			return verifyObjectWrite(mutation, mods, "")
		}
		return nil
	})
	return result, err
}
