package model

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
	Principal IdentityResult
	Outcomes  []PrincipalMembershipOutcome
	Processed int
	Complete  bool
}
