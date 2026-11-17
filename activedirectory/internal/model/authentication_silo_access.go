package model

type AuthenticationPolicySiloAccessRequest struct {
	Identity, Account Identity
	Options           ObjectMutationOptions
	MaxMembers        int
}

type AuthenticationPolicySiloAccessResult struct {
	Mutation           ObjectMutationResult
	AccountObservation IdentityResult
	Members            AuthenticationSiloLinks
}

// The two account links are independently omitted, assigned, or explicitly
// cleared. A combined change is one atomic LDAP Modify on that account.
type SetAccountAuthenticationPolicySiloRequest struct {
	Identity               Identity
	Silo, Policy           *Identity
	ClearSilo, ClearPolicy bool
	// RequireGranted is an optional positive-observation precondition. The
	// default permits staging assignment before grant, as the module does.
	// This cross-object read is not an atomic server assertion on the silo.
	RequireGranted bool
	MaxMembers     int
	Options        ObjectMutationOptions
}

type AccountAuthenticationPolicySiloResult struct {
	Mutation                           ObjectMutationResult
	SiloObservation, PolicyObservation IdentityResult
	GrantObservation                   AuthenticationSiloLinks
}
