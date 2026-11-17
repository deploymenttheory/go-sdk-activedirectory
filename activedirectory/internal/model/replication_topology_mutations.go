package model

import (
	"errors"
	"strings"
)

func InternalTopologyMutationInput(identity Identity, options ObjectMutationOptions) error {
	if err := InternalTopologyIdentity(
		identity,
		ResolveIdentityOptions{Partition: options.Partition, Properties: options.Properties},
	); err != nil {
		return err
	}
	return InternalValidateObjectOptions(identity, options)
}

func InternalTopologyTextChange(name string, value *string) []AttributeChange {
	if value == nil {
		return nil
	}
	return []AttributeChange{
		{Attribute: name, Kind: AttributeSet, Values: []RawValue{NewRawValue([]byte(*value))}},
	}
}

func InternalTopologyValidateChanges(
	changes []AttributeChange,
	managed []string,
) ([]InternalLdapAttributeModification, error) {
	for _, change := range changes {
		for _, name := range managed {
			if strings.EqualFold(change.Attribute, name) {
				return nil, ErrReplicationTopology
			}
		}
	}
	return InternalObjectChanges(changes)
}

func InternalTopologyStep(
	result *ReplicationSiteMutationResult,
	name string,
	mutation ObjectMutationResult,
	err error,
) error {
	result.Steps = append(
		result.Steps,
		ReplicationTopologyStep{Name: name, Mutation: mutation, Error: err},
	)
	return err
}

// topologyIncompleteError reports a failed site change that had already had at
// least one object write accepted, which leaves the directory holding part of
// the change.
//
// Without it the returned error carries only the failure that stopped the
// sequence. A third write refused with LDAP 50 reports as access denied, which
// says nothing about the two objects already created and reads as though the
// whole change was rejected — so a caller tracking state records nothing and
// the accepted objects become invisible to it. The step results always held
// this, but only a caller that knew to walk Steps could see it.
//
// A step accepted and then found unverifiable is already reported through
// ErrObjectReadback, and an uncertain write through ErrObjectWriteUncertain;
// both classify as uncertain, so joining this alongside them is consistent
// rather than contradictory.
func InternalTopologyIncompleteError(result ReplicationSiteMutationResult, err error) error {
	if err == nil {
		return nil
	}
	for _, step := range result.Steps {
		if step.Mutation.State == ObjectWriteAccepted ||
			step.Mutation.State == ObjectWriteUncertain {
			return errors.Join(ErrReplicationTopologyIncomplete, err)
		}
	}
	return err
}

func InternalTopologyAfterMutationError(mutation ObjectMutationResult, err error) error {
	if err != nil && mutation.State == ObjectWriteAccepted {
		return errors.Join(ErrObjectReadback, err)
	}
	return err
}
