package model

import "errors"

var ErrPrincipalMembershipIncomplete = errors.New("principal membership change has accepted or uncertain effects; reconcile individual groups before another write")

type PrincipalMembershipTarget struct {
	Identity Identity
	Options  ObjectMutationOptions
}
type PrincipalGroupMembershipRequest struct {
	Principal Identity
	Partition string
	Groups    []PrincipalMembershipTarget
	Mode      GroupMembershipMode
}
type PrincipalMembershipOutcome struct {
	Group  Identity
	Result GroupMembershipMutationResult
	Error  error
}

// Each group is an independent Modify. Known failures retain per-target results;
// uncertainty or cancellation stops all remaining targets without replay.
type PrincipalGroupMembershipMutationResult struct {
	// Mutation aggregates the non-atomic batch: any uncertain request wins,
	// otherwise any accepted request, then rejection, then not-attempted.
	// PartialEffectsPossible signals an incomplete batch with effects. No single
	// TargetGUID/Before/After is invented; inspect Outcomes for each actual group.
	// Complete does not imply Verified: group identity reads do not prove edges.
	Mutation  ObjectMutationResult
	Principal IdentityResult
	Outcomes  []PrincipalMembershipOutcome
	Processed int
	Complete  bool
}

func InternalFinishPrincipalMembershipMutation(result *PrincipalGroupMembershipMutationResult, err error) error {
	mutations := make([]ObjectMutationResult, len(result.Outcomes))
	for i, outcome := range result.Outcomes {
		mutations[i] = outcome.Result.Mutation
	}
	result.Mutation = InternalAggregateObjectMutations(mutations, result.Complete)
	if result.Mutation.Source.Host == "" {
		result.Mutation.Source = result.Principal.Source
	}
	if err != nil && (result.Mutation.State == ObjectWriteAccepted || result.Mutation.State == ObjectWriteUncertain) {
		return errors.Join(ErrPrincipalMembershipIncomplete, err)
	}
	return err
}
