package model

import (
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
type InternalCentralAccessSyntaxSession interface {
	InternalValidateCentralAccessDescriptor(string) error
	InternalValidateCentralAccessCondition(string) error
}

func InternalCentralAccessText(name string, value *string) []AttributeChange {
	if value == nil {
		return nil
	}
	return []AttributeChange{
		{Attribute: name, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*value))}},
	}
}

func InternalCentralAccessRawChanges(changes []AttributeChange) error {
	for _, change := range changes {
		for _, managed := range []string{
			"cn", "name", InternalCentralCurrent, InternalCentralProposed, InternalCentralPrevious, InternalCentralCondition,
			InternalCentralPolicyID, InternalCentralMembers, InternalCentralMemberOf, "nTSecurityDescriptor",
		} {
			if strings.EqualFold(change.Attribute, managed) {
				return ErrCentralAccess
			}
		}
	}
	return nil
}

func InternalCentralAccessProtectionCapability(
	session InternalDirectorySession,
	root RootDSE,
	protect *bool,
) error {
	if protect == nil {
		return nil
	}
	if _, ok := session.(InternalOuProtectionSession); !ok {
		return ErrUnsupported
	}
	if !slices.Contains(root.SupportedControls, InternalOuSDFlagsControl) {
		return ErrObjectControlUnsupported
	}
	return nil
}

func InternalCentralAccessValidateSyntax(
	session InternalDirectorySession,
	attributes map[string][]RawValue,
) error {
	var syntax InternalCentralAccessSyntaxSession
	for _, name := range []string{InternalCentralCurrent, InternalCentralProposed, InternalCentralCondition} {
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
			syntax, ok = session.(InternalCentralAccessSyntaxSession)
			if !ok {
				return ErrUnsupported
			}
		}
		if name == InternalCentralCondition {
			err = syntax.InternalValidateCentralAccessCondition(text)
		} else {
			err = syntax.InternalValidateCentralAccessDescriptor(text)
		}
		if err != nil {
			return errors.Join(ErrCentralAccess, err)
		}
	}
	return nil
}

func InternalCentralAccessProject(
	result CentralAccessMutationResult,
	policy bool,
	err error,
) (CentralAccessMutationResult, error) {
	if result.Mutation.After != nil {
		if policy {
			value, e := InternalDecodeCentralAccessPolicy(*result.Mutation.After)
			value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
			result.Policy = &value
			err = errors.Join(err, e)
		} else {
			value, e := InternalDecodeCentralAccessRule(*result.Mutation.After)
			value.ProtectedFromAccidentalDeletion = result.Protection.ProtectedFromAccidentalDeletion
			result.Rule = &value
			err = errors.Join(err, e)
		}
	}
	return result, err
}

func InternalCentralAccessCreateInput(
	name string,
	description *string,
	options ObjectMutationOptions,
) error {
	if name == "" || !InternalValidDirectoryText(name) ||
		(description != nil && !InternalValidDirectoryText(*description)) {
		return ErrInvalidObjectMutation
	}
	if options.ExpectedVersion != nil {
		return ErrObjectControlUnsupported
	}
	return nil
}

func InternalCentralAccessRuleChanges(
	request UpdateCentralAccessRuleRequest,
) ([]AttributeChange, error) {
	if request.CurrentACL != nil && request.ClearCurrentACL ||
		request.ProposedACL != nil && request.ClearProposedACL ||
		request.ResourceCondition != nil && request.ClearResourceCondition {
		return nil, ErrCentralAccess
	}
	if err := InternalCentralAccessRawChanges(request.Changes); err != nil {
		return nil, err
	}
	changes := InternalCentralAccessText("description", request.Description)
	changes = append(
		changes,
		InternalCentralAccessText(InternalCentralProposed, request.ProposedACL)...)
	if request.ClearProposedACL {
		changes = append(
			changes,
			AttributeChange{Attribute: InternalCentralProposed, Kind: AttributeClear},
		)
	}
	if request.ResourceCondition != nil {
		text, err := request.ResourceCondition.Render()
		if err != nil {
			return nil, err
		}
		changes = append(changes, InternalCentralAccessText(InternalCentralCondition, &text)...)
	} else if request.ClearResourceCondition {
		changes = append(
			changes,
			AttributeChange{Attribute: InternalCentralCondition, Kind: AttributeClear},
		)
	}
	return append(changes, request.Changes...), nil
}
