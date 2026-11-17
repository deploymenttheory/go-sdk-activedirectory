package model

type AuthorizationGroupSIDResult struct {
	SID     SID
	Lookups []MembershipSearch
	Error   error
}

// TokensComplete means the server returned every contiguous tokenGroups range.
// Complete additionally requires every SID to resolve to a security group in
// the supplied contexts. Neither is a Windows logon token or access-check result.
type AccountAuthorizationGroupsResult struct {
	Account                                IdentityResult
	SIDs                                   []SID
	Groups                                 []Group
	Resolutions                            []AuthorizationGroupSIDResult
	Ranges                                 []GroupMemberRange
	TokensComplete, Complete, LimitReached bool
}
