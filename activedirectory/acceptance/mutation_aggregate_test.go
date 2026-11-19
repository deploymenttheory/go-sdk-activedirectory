package acceptance

import (
	"context"
	"errors"
	"io"
	"testing"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
	replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

func TestPrincipalMembershipEarlierAcceptedEffectCannotBeHiddenByDenial(t *testing.T) {
	principal := InternalMembershipObject("principal", "DC=example", "user", 1, 1100, 1)
	groups := []admodel.Object{
		InternalMembershipObject("allowed", "DC=example", "group", 2, 1000, 1),
		InternalMembershipObject("denied", "DC=example", "group", 3, 1001, 1),
	}
	writes := 0
	world := InternalMembershipWorld{
		InternalObjects: append([]admodel.Object{principal}, groups...),
		InternalWrite: func(admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
			writes++
			if writes == 1 {
				return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
			}
			return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 50}}
		},
	}
	result, err := memberships.New(world.InternalClient(t)).AddPrincipalGroupMembership(t.Context(), memberships.PrincipalGroupMembershipRequest{
		Principal: InternalGroupMemberDN(t, principal.DistinguishedName),
		Groups: []memberships.PrincipalMembershipTarget{
			{Identity: InternalGroupMemberDN(t, groups[0].DistinguishedName)}, {Identity: InternalGroupMemberDN(t, groups[1].DistinguishedName)},
		},
		Mode: memberships.GroupMembershipStrict,
	})
	var status *ad.LDAPError
	if ad.Classify(err) != ad.ClassUncertain || !errors.As(err, &status) || status.Code != 50 || result.Complete || writes != 2 ||
		!errors.Is(err, memberships.ErrPrincipalMembershipIncomplete) || result.Mutation.State != ad.ObjectWriteAccepted ||
		!result.Mutation.PartialEffectsPossible || result.Mutation.Verified || result.Mutation.TargetGUID != nil || result.Mutation.Before != nil || result.Mutation.After != nil ||
		len(result.Outcomes) != 2 || result.Outcomes[0].Result.Mutation.State != ad.ObjectWriteAccepted ||
		result.Outcomes[1].Result.Mutation.State != ad.ObjectWriteRejected {
		t.Fatal("later denial concealed an already accepted independent membership change", result, err)
	}
}

func TestPrincipalMembershipAggregateKeepsCancellationAndUnknownEffectsDistinct(t *testing.T) {
	for _, mode := range []string{"complete", "lost", "cancel-before", "cancel-after-accepted"} {
		t.Run(mode, func(t *testing.T) {
			principal := InternalMembershipObject("principal", "DC=example", "user", 1, 1100, 1)
			groups := []admodel.Object{
				InternalMembershipObject("first", "DC=example", "group", 2, 1000, 1),
				InternalMembershipObject("second", "DC=example", "group", 3, 1001, 1),
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			writes := 0
			world := InternalMembershipWorld{
				InternalObjects: append([]admodel.Object{principal}, groups...),
				InternalWrite: func(admodel.InternalLdapWriteRequest) admodel.InternalLdapWriteAttempt {
					writes++
					if mode == "cancel-after-accepted" {
						cancel()
					}
					if mode == "lost" && writes == 2 {
						return admodel.InternalLdapWriteAttempt{
							State: admodel.InternalLdapWriteUncertain, Err: errors.Join(admodel.InternalLDAPWriteUncertainError(), io.ErrUnexpectedEOF),
						}
					}
					return admodel.InternalLdapWriteAttempt{State: admodel.InternalLdapWriteAccepted}
				},
			}
			if mode == "cancel-before" {
				cancel()
			}
			result, err := memberships.New(world.InternalClient(t)).AddPrincipalGroupMembership(ctx, memberships.PrincipalGroupMembershipRequest{
				Principal: InternalGroupMemberDN(t, principal.DistinguishedName),
				Groups: []memberships.PrincipalMembershipTarget{
					{Identity: InternalGroupMemberDN(t, groups[0].DistinguishedName)}, {Identity: InternalGroupMemberDN(t, groups[1].DistinguishedName)},
				}, Mode: memberships.GroupMembershipStrict,
			})
			if result.Mutation.TargetGUID != nil || result.Mutation.Before != nil || result.Mutation.After != nil {
				t.Fatal("multi-object batch invented a single target observation")
			}
			switch mode {
			case "complete":
				// The existing group contract observes identity, not the complete
				// linked membership. Completion must not manufacture verification.
				if err != nil || !result.Complete || result.Mutation.State != ad.ObjectWriteAccepted ||
					result.Mutation.Verified || result.Mutation.PartialEffectsPossible || writes != 2 {
					t.Fatal("completed membership batch changed its observation boundary", result, err)
				}
			case "cancel-before":
				if !errors.Is(err, context.Canceled) || errors.Is(err, memberships.ErrPrincipalMembershipIncomplete) || writes != 0 ||
					result.Mutation.State != ad.ObjectWriteNotAttempted || result.Mutation.PartialEffectsPossible {
					t.Fatal("cancellation before any write manufactured effects", result, err)
				}
			case "cancel-after-accepted":
				if !errors.Is(err, context.Canceled) || !errors.Is(err, memberships.ErrPrincipalMembershipIncomplete) || writes != 1 ||
					result.Mutation.State != ad.ObjectWriteAccepted || !result.Mutation.PartialEffectsPossible || result.Complete {
					t.Fatal("cancellation erased an acknowledged effect or allowed another write", result, err)
				}
			case "lost":
				if !errors.Is(err, io.ErrUnexpectedEOF) || ad.Classify(err) != ad.ClassUncertain || writes != 2 ||
					result.Mutation.State != ad.ObjectWriteUncertain || !result.Mutation.PartialEffectsPossible || result.Complete ||
					result.Outcomes[0].Result.Mutation.State != ad.ObjectWriteAccepted {
					t.Fatal("unknown second outcome concealed the accepted first group", result, err)
				}
			}
		})
	}
}

func TestReplicationSiteAggregateCanVerifyTheCompletedSequence(t *testing.T) {
	client, _ := InternalNewTopologyTestClient(t, false)
	result, err := replication.New(client).CreateReplicationSite(t.Context(), replication.CreateReplicationSiteRequest{Name: "Verified"})
	if err != nil || !result.Complete || !result.Mutation.Verified || !result.Mutation.ReadbackComplete ||
		result.Mutation.State != ad.ObjectWriteAccepted || result.Mutation.PartialEffectsPossible || result.Mutation.TargetGUID == nil ||
		result.After.Site == nil || result.After.Site.GUID == nil || *result.Mutation.TargetGUID != *result.After.Site.GUID {
		t.Fatal("fully observed site sequence was not retained uniformly", result, err)
	}
}

func TestReplicationSiteAggregateRetainsRootIdentityAcrossChildRefusal(t *testing.T) {
	client, directory := InternalNewTopologyTestClient(t, false)
	directory.InternalFailAt = 3
	directory.InternalFailure = admodel.InternalLdapWriteAttempt{
		State: admodel.InternalLdapWriteRejected, Err: &admodel.LDAPError{Code: 50},
	}
	result, err := replication.New(client).CreateReplicationSite(t.Context(), replication.CreateReplicationSiteRequest{Name: "Owned"})
	if ad.Classify(err) != ad.ClassUncertain || result.Complete || result.Mutation.State != ad.ObjectWriteAccepted ||
		!result.Mutation.PartialEffectsPossible || result.Mutation.Verified || len(result.Steps) != 3 || result.Mutation.TargetGUID == nil ||
		result.Steps[0].Mutation.TargetGUID == nil || *result.Mutation.TargetGUID != *result.Steps[0].Mutation.TargetGUID ||
		result.Mutation.TargetDN != result.Steps[0].Mutation.TargetDN || result.Mutation.After == nil {
		t.Fatal("site aggregate lost accepted root identity behind a child refusal", result, err)
	}
	var status *ad.LDAPError
	if !errors.As(err, &status) || status.Code != 50 || result.Steps[1].Mutation.TargetGUID == nil ||
		*result.Steps[1].Mutation.TargetGUID == *result.Mutation.TargetGUID {
		t.Fatal("site aggregate confused a child identity or lost original refusal", err)
	}
}
