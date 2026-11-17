package model

type GroupMembershipTraversal struct {
	Source         Endpoint
	Depth          int
	Links          GroupMemberLinksResult
	Resolutions    []MembershipResolution
	PrimaryMembers SearchResult
}

// Complete means every requested traversal, range and resolution completed.
// It does not prove ACL visibility or a transactionally consistent graph. Each
// Links.AttributeReturned preserves omission without proving no hidden members.
type GroupMembersResult struct {
	Members                []MembershipPrincipal
	Groups                 []GroupMembershipTraversal
	Unresolved             []MembershipResolution
	Complete, LimitReached bool
}
