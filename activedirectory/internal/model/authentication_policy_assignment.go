package model

// SetAccountAuthenticationPolicyRequest assigns Policy or explicitly clears
// the direct policy link. Exactly one of Policy/Clear must be supplied. Account
// identities use the existing DN/GUID/SID/SAM rules; Policy accepts DN/GUID.
// Silo membership/assignment is not changed and may override this direct link
// during authentication. This result never claims an effective resultant policy.
type SetAccountAuthenticationPolicyRequest struct {
	Identity Identity
	Policy   *Identity
	Clear    bool
	Options  ObjectMutationOptions
}

type AccountAuthenticationPolicyResult struct {
	Mutation          ObjectMutationResult
	Policy            *AuthenticationPolicy
	PolicyObservation IdentityResult
}
