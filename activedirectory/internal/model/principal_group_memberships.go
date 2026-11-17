package model

// Complete covers these direct membership searches, not transitive membership,
// ACL visibility, replication convergence or authorization. ResourceContext
// returns only its specified NC. No automatic cross-forest lookup occurs.
type PrincipalGroupMembershipResult struct {
	Principal              IdentityResult
	Groups                 []Group
	PrimaryGroup           *MembershipLookup
	ResourcePrincipal      *MembershipLookup
	Searches               []MembershipSearch
	Complete, LimitReached bool
}
