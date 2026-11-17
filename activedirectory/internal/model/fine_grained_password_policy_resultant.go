package model

// UserResultantPasswordPolicyResult reports the server's constructed
// msDS-ResultantPSO value. NotReturned is an observation: it does not prove the
// default domain policy applies when ACLs hide an attribute. No local policy
// precedence or group expansion substitutes for the constructed value.
type UserResultantPasswordPolicyResult struct {
	User                  IdentityResult
	Policy                FineGrainedPasswordPolicyResult
	PolicyDN              *string
	AttributeState        AttributeState
	NotReturned, Complete bool
}
