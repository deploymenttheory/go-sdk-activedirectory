package activedirectory

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-sdk-activedirectory/conditions"
)

type CreateCentralAccessRuleRequest struct {
	Name                                 string
	Description, CurrentACL, ProposedACL *string
	ResourceCondition                    *conditions.Expression
	ProtectedFromAccidentalDeletion      *bool
	Options                              ObjectMutationOptions
}
type UpdateCentralAccessRuleRequest struct {
	Identity                                                  Identity
	Description, CurrentACL, ProposedACL                      *string
	ResourceCondition                                         *conditions.Expression
	ClearCurrentACL, ClearProposedACL, ClearResourceCondition bool
	ProtectedFromAccidentalDeletion                           *bool
	Changes                                                   []AttributeChange
	Options                                                   ObjectMutationOptions
}
type CreateCentralAccessPolicyRequest struct {
	Name                            string
	Description                     *string
	ProtectedFromAccidentalDeletion *bool
	Options                         ObjectMutationOptions
}
type UpdateCentralAccessPolicyRequest struct {
	Identity                        Identity
	Description                     *string
	ProtectedFromAccidentalDeletion *bool
	Changes                         []AttributeChange
	Options                         ObjectMutationOptions
}
type CentralAccessMutationResult struct {
	Mutation   ObjectMutationResult
	Protection OUProtectionResult
	Rule       *CentralAccessRule
	Policy     *CentralAccessPolicy
	// GeneratedPolicyID is retained even if the Add is rejected or uncertain.
	GeneratedPolicyID *SID
}
type centralAccessSyntaxSession interface {
	validateCentralAccessDescriptor(string) error
	validateCentralAccessCondition(string) error
}

func (c *Client) centralAccessMutationContext(ctx context.Context, options ObjectMutationOptions) (context.Context, context.CancelFunc, ObjectMutationOptions, error) {
	if c == nil || c.session == nil {
		return ctx, func() {}, options, ErrClosed
	}
	bounded, cancel := context.WithTimeout(ctx, c.config.Timeout)
	root, err := c.RootDSE(bounded, RootDSEOptions{})
	if err == nil {
		options.Partition, err = centralAccessConfiguration(root, c.config, options.Partition)
	}
	if err != nil {
		cancel()
	}
	return bounded, cancel, options, err
}
func centralAccessText(name string, value *string) []AttributeChange {
	if value == nil {
		return nil
	}
	return []AttributeChange{{Attribute: name, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*value))}}}
}
func centralAccessRawChanges(changes []AttributeChange) error {
	for _, change := range changes {
		for _, managed := range []string{"cn", "name", centralCurrent, centralProposed, centralPrevious, centralCondition, centralPolicyID, centralMembers, centralMemberOf, "nTSecurityDescriptor"} {
			if strings.EqualFold(change.Attribute, managed) {
				return ErrCentralAccess
			}
		}
	}
	return nil
}
func centralAccessProtectionCapability(session directorySession, root RootDSE, protect *bool) error {
	if protect == nil {
		return nil
	}
	if _, ok := session.(ouProtectionSession); !ok {
		return ErrUnsupported
	}
	if !slices.Contains(root.SupportedControls, ouSDFlagsControl) {
		return ErrObjectControlUnsupported
	}
	return nil
}
func centralAccessValidateSyntax(session directorySession, attributes map[string][]RawValue) error {
	var syntax centralAccessSyntaxSession
	for _, name := range []string{centralCurrent, centralProposed, centralCondition} {
		values, found := attributes[name]
		if !found {
			continue
		}
		if len(values) != 1 {
			return ErrInvalidValue
		}
		text, err := values[0].Text()
		if err != nil {
			return err
		}
		if syntax == nil {
			var ok bool
			syntax, ok = session.(centralAccessSyntaxSession)
			if !ok {
				return ErrUnsupported
			}
		}
		if name == centralCondition {
			err = syntax.validateCentralAccessCondition(text)
		} else {
			err = syntax.validateCentralAccessDescriptor(text)
		}
		if err != nil {
			return errors.Join(ErrCentralAccess, err)
		}
	}
	return nil
}
func centralAccessProject(result CentralAccessMutationResult, policy bool, err error) (CentralAccessMutationResult, error) {
	if result.Mutation.After != nil {
		if policy {
			value, e := decodeCentralAccessPolicy(*result.Mutation.After)
			value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
			result.Policy = &value
			err = errors.Join(err, e)
		} else {
			value, e := decodeCentralAccessRule(*result.Mutation.After)
			value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
			result.Rule = &value
			err = errors.Join(err, e)
		}
	}
	return result, err
}
func centralAccessCreateInput(name string, description *string, options ObjectMutationOptions) error {
	if name == "" || !validDirectoryText(name) || (description != nil && !validDirectoryText(*description)) {
		return ErrInvalidObjectMutation
	}
	if options.ExpectedVersion != nil {
		return ErrObjectControlUnsupported
	}
	return nil
}
func (c *Client) createCentralAccess(ctx context.Context, name string, description *string, attrs map[string][]RawValue, protect *bool, options ObjectMutationOptions, policy bool, result CentralAccessMutationResult) (CentralAccessMutationResult, error) {
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, options)
	if err != nil {
		return result, err
	}
	defer cancel()
	err = c.read(ctx, func(ctx context.Context) error {
		root, e := readIdentityRoot(ctx, c.session)
		if e != nil {
			return e
		}
		if e := centralAccessProtectionCapability(c.session, root, protect); e != nil {
			return e
		}
		return centralAccessValidateSyntax(c.session, attrs)
	})
	if err != nil {
		return result, err
	}
	if description != nil {
		attrs["description"] = []RawValue{NewRawValue([]byte(*description))}
	}
	parent, _ := IdentityByDN(centralAccessParent(options.Partition, policy))
	options.Properties = centralAccessProperties(options.Properties, policy)
	result.Mutation, err = c.CreateObject(ctx, CreateObjectRequest{Parent: parent, Class: centralAccessClass(policy), Name: name, Attributes: attrs, Options: options})
	if err != nil {
		return centralAccessProject(result, policy, err)
	}
	if protect != nil {
		protection, e := c.setCentralAccessProtection(ctx, objectGUIDIdentity(*result.Mutation.TargetGUID), *protect, ObjectMutationOptions{Partition: options.Partition}, policy)
		result.Protection = protection
		err = e
	}
	return centralAccessProject(result, policy, err)
}
func (c *Client) CreateCentralAccessRule(ctx context.Context, request CreateCentralAccessRuleRequest) (CentralAccessMutationResult, error) {
	var result CentralAccessMutationResult
	if err := centralAccessCreateInput(request.Name, request.Description, request.Options); err != nil {
		return result, err
	}
	current := DefaultCentralAccessRuleACL
	if request.CurrentACL != nil {
		current = *request.CurrentACL
	}
	attrs := map[string][]RawValue{centralCurrent: {NewRawValue([]byte(current))}}
	if request.ProposedACL != nil {
		attrs[centralProposed] = []RawValue{NewRawValue([]byte(*request.ProposedACL))}
	}
	if request.ResourceCondition != nil {
		text, err := request.ResourceCondition.Render()
		if err != nil {
			return result, err
		}
		attrs[centralCondition] = []RawValue{NewRawValue([]byte(text))}
	}
	return c.createCentralAccess(ctx, request.Name, request.Description, attrs, request.ProtectedFromAccidentalDeletion, request.Options, false, result)
}
func (c *Client) CreateCentralAccessPolicy(ctx context.Context, request CreateCentralAccessPolicyRequest) (CentralAccessMutationResult, error) {
	var result CentralAccessMutationResult
	if err := centralAccessCreateInput(request.Name, request.Description, request.Options); err != nil {
		return result, err
	}
	sid, err := newCentralAccessPolicyID()
	if err != nil {
		return result, err
	}
	result.GeneratedPolicyID = &sid
	return c.createCentralAccess(ctx, request.Name, request.Description, map[string][]RawValue{centralPolicyID: {NewRawValue(sid.Bytes())}}, request.ProtectedFromAccidentalDeletion, request.Options, true, result)
}
func centralAccessRuleChanges(request UpdateCentralAccessRuleRequest) ([]AttributeChange, error) {
	if request.CurrentACL != nil && request.ClearCurrentACL || request.ProposedACL != nil && request.ClearProposedACL || request.ResourceCondition != nil && request.ClearResourceCondition {
		return nil, ErrCentralAccess
	}
	if err := centralAccessRawChanges(request.Changes); err != nil {
		return nil, err
	}
	changes := centralAccessText("description", request.Description)
	changes = append(changes, centralAccessText(centralProposed, request.ProposedACL)...)
	if request.ClearProposedACL {
		changes = append(changes, AttributeChange{Attribute: centralProposed, Kind: AttributeClear})
	}
	if request.ResourceCondition != nil {
		text, err := request.ResourceCondition.Render()
		if err != nil {
			return nil, err
		}
		changes = append(changes, centralAccessText(centralCondition, &text)...)
	} else if request.ClearResourceCondition {
		changes = append(changes, AttributeChange{Attribute: centralCondition, Kind: AttributeClear})
	}
	return append(changes, request.Changes...), nil
}
func (c *Client) UpdateCentralAccessRule(ctx context.Context, request UpdateCentralAccessRuleRequest) (CentralAccessMutationResult, error) {
	changes, err := centralAccessRuleChanges(request)
	if err != nil {
		return CentralAccessMutationResult{}, err
	}
	return c.updateCentralAccess(ctx, request.Identity, request.Options, changes, request.CurrentACL, request.ClearCurrentACL, request.ProtectedFromAccidentalDeletion, false)
}
func (c *Client) UpdateCentralAccessPolicy(ctx context.Context, request UpdateCentralAccessPolicyRequest) (CentralAccessMutationResult, error) {
	if err := centralAccessRawChanges(request.Changes); err != nil {
		return CentralAccessMutationResult{}, err
	}
	return c.updateCentralAccess(ctx, request.Identity, request.Options, append(centralAccessText("description", request.Description), request.Changes...), nil, false, request.ProtectedFromAccidentalDeletion, true)
}
func (c *Client) updateCentralAccess(ctx context.Context, identity Identity, options ObjectMutationOptions, changes []AttributeChange, current *string, clearCurrent bool, protect *bool, policy bool) (CentralAccessMutationResult, error) {
	var result CentralAccessMutationResult
	if err := validateObjectOptions(identity, options); err != nil {
		return result, err
	}
	var mods []ldapAttributeModification
	var err error
	if len(changes) > 0 {
		mods, err = objectChanges(changes)
		if err != nil {
			return result, err
		}
	}
	if protect != nil && options.ExpectedVersion != nil && (*protect || len(mods) > 0 || current != nil || clearCurrent) {
		return result, ErrObjectControlUnsupported
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, options)
	if err != nil {
		return result, err
	}
	defer cancel()
	result.Mutation, err = c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{Properties: centralAccessProperties(options.Properties, policy)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := centralAccessLocation(*observed.Object, options.Partition, policy); err != nil {
			return err
		}
		if err := centralAccessProtectionCapability(session, root, protect); err != nil {
			return err
		}
		validation := map[string][]RawValue{}
		for _, mod := range mods {
			if len(mod.values) == 1 {
				validation[mod.attribute] = []RawValue{NewRawValue(mod.values[0])}
			}
		}
		if current != nil {
			validation[centralCurrent] = []RawValue{NewRawValue([]byte(*current))}
		}
		if err := centralAccessValidateSyntax(session, validation); err != nil {
			return err
		}
		if current != nil || clearCurrent {
			// Strictly replace the observed current value and record that same
			// value as PreviousACL atomically. Hidden current permissions cannot
			// be treated as empty; concurrent replacement must reject this write.
			old, err := observed.Object.Values(centralCurrent).Single()
			if err != nil {
				return err
			}
			mods = append(mods, ldapAttributeModification{operation: 1, attribute: centralCurrent, values: [][]byte{old.Bytes()}})
			if current != nil {
				mods = append(mods, ldapAttributeModification{operation: 0, attribute: centralCurrent, values: [][]byte{[]byte(*current)}})
			}
			mods = append(mods, ldapAttributeModification{operation: 2, attribute: centralPrevious, values: [][]byte{old.Bytes()}})
		}
		if len(mods) == 0 {
			if options.ExpectedVersion != nil && protect == nil {
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
			readOptions.Properties = centralAccessProperties(options.Properties, policy)
			if err := observeObjectWrite(ctx, session, c.config, root, objectGUIDIdentity(*mutation.TargetGUID), mutation, objectWriteProperties(readOptions, mods), false); err != nil {
				return err
			}
			verification := slices.Clone(mods)
			// A strict remove/add of identical text is a legitimate write; its
			// final effect is replacement, not simultaneous absence/presence.
			if current != nil {
				verification = slices.DeleteFunc(verification, func(mod ldapAttributeModification) bool {
					return strings.EqualFold(mod.attribute, centralCurrent) && mod.operation == 1
				})
			}
			if err := verifyObjectWrite(mutation, verification, ""); err != nil {
				return err
			}
		}
		if protect != nil {
			result.Protection.Object = *mutation
			return changeOUProtection(ctx, session, root, c.config, mutation, *protect, options, &result.Protection)
		}
		return nil
	})
	return centralAccessProject(result, policy, err)
}
func (c *Client) setCentralAccessProtection(ctx context.Context, identity Identity, protect bool, options ObjectMutationOptions, policy bool) (OUProtectionResult, error) {
	var result OUProtectionResult
	var err error
	result.Object, err = c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{Properties: centralAccessProperties(options.Properties, policy)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, mutation *ObjectMutationResult) error {
		if err := centralAccessLocation(*observed.Object, options.Partition, policy); err != nil {
			return err
		}
		return changeOUProtection(ctx, session, root, c.config, mutation, protect, options, &result)
	})
	return result, err
}
func (c *Client) deleteCentralAccess(ctx context.Context, identity Identity, options ObjectMutationOptions, policy bool) (ObjectMutationResult, error) {
	if err := validateObjectOptions(identity, options); err != nil {
		return ObjectMutationResult{}, err
	}
	ctx, cancel, options, err := c.centralAccessMutationContext(ctx, options)
	if err != nil {
		return ObjectMutationResult{}, err
	}
	defer cancel()
	return c.objectMutationIdentity(ctx, identity, options, ResolveIdentityOptions{Properties: centralAccessProperties(options.Properties, policy)}, func(ctx context.Context, session ldapWriteSession, root RootDSE, observed IdentityResult, result *ObjectMutationResult) error {
		if err := centralAccessLocation(*observed.Object, options.Partition, policy); err != nil {
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

// Deletes submit one native leaf delete. They never unprotect an object, remove
// rule memberships separately, or delete referenced rules/policies. Native
// referential-integrity and access-check outcomes remain authoritative.
func (c *Client) DeleteCentralAccessRule(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	return c.deleteCentralAccess(ctx, identity, options, false)
}
func (c *Client) DeleteCentralAccessPolicy(ctx context.Context, identity Identity, options ObjectMutationOptions) (ObjectMutationResult, error) {
	return c.deleteCentralAccess(ctx, identity, options, true)
}
