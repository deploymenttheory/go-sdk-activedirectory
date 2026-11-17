package model

// One request changes one explicit list in one atomic Modify. Reuse the direct
// membership strict/permissive semantics and common concurrency controls. No
// secret replication, cache eviction, cross-domain lookup or automatic replay.
type RODCPasswordReplicationChange struct {
	Controller Identity
	List       RODCPasswordReplicationList
	Principals []Identity
	Mode       GroupMembershipMode
	Options    ObjectMutationOptions
}
type RODCPasswordReplicationMutationResult struct {
	Mutation   ObjectMutationResult
	Principals []GroupMemberInput
}
