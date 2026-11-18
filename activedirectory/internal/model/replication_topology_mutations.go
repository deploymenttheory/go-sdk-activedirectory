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

func InternalFinishReplicationSiteMutation(result *ReplicationSiteMutationResult, err error) error {
	mutations := make([]ObjectMutationResult, len(result.Steps))
	for i, step := range result.Steps {
		mutations[i] = step.Mutation
	}
	aggregate := InternalAggregateObjectMutations(mutations, result.Complete)
	aggregate.PreflightCandidates = result.Preflight.Candidates
	if before := result.Preflight.Object; before != nil {
		aggregate.Before, aggregate.TargetDN = before, before.DistinguishedName
		if guid, guidErr := InternalTopologyGUID(*before); guidErr == nil {
			aggregate.TargetGUID = &guid
		}
	}
	for _, step := range result.Steps {
		if step.Name != "site" {
			continue
		}
		root := step.Mutation
		aggregate.TargetDN, aggregate.TargetGUID = root.TargetDN, root.TargetGUID
		aggregate.Before, aggregate.After = root.Before, root.After
		aggregate.PreflightCandidates, aggregate.ReadbackCandidates = root.PreflightCandidates, root.ReadbackCandidates
		aggregate.AbsentAfter = root.AbsentAfter
	}
	if after := result.After.Site; after != nil {
		aggregate.After = &after.Raw
		aggregate.TargetDN = InternalObservedDistinguishedName(&after.Raw)
		aggregate.TargetGUID = after.GUID
		aggregate.Verified = aggregate.Verified && result.After.Complete
		aggregate.ReadbackComplete = aggregate.ReadbackComplete && result.After.Complete
	}
	if len(result.After.Observation.Candidates) != 0 {
		aggregate.ReadbackCandidates = result.After.Observation.Candidates
	}
	if aggregate.Source.Host == "" {
		aggregate.Source = result.Preflight.Source
	}
	if aggregate.Partition == "" {
		aggregate.Partition = result.Preflight.Partition
	}
	result.Mutation = aggregate
	return InternalTopologyIncompleteError(*result, err)
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
