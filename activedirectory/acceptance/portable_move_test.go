package acceptance

import (
	"errors"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableCrossDomainMoveUsesActualDelegationAndKeepsWriteOutcomes(t *testing.T) {
	for _, fault := range []string{"", "refused", "lost-ack", "partial-destination", "wrong-RID", "other-forest", "not-requested"} {
		t.Run(fault, func(t *testing.T) {
			source, destination, directory, retire := newPortableMoveWireClients(t, fault)
			request := directory.data.InternalRequest
			request.Destination = destination
			result, err := source.MoveObject(t.Context(), request)
			if fault == "wrong-RID" || fault == "not-requested" || fault == "other-forest" {
				want := admodel.ErrMoveRIDMaster
				if fault == "not-requested" {
					want = admodel.ErrMoveDelegation
				}
				if fault == "other-forest" {
					want = admodel.ErrMoveForest
				}
				if !errors.Is(err, want) || result.Mutation.State != admodel.ObjectWriteNotAttempted || directory.submits != 0 {
					t.Fatalf("unsafe preflight submitted a move: %+v, %v", result.Mutation, err)
				}
				retire()
				return
			}
			if directory.submits != 1 || len(directory.controls) != 1 || result.Mutation.TargetGUID == nil || result.Mutation.Before == nil ||
				result.Mutation.Source.Host != portableTLSHost || result.Destination.Host != "dst.child.example" ||
				result.Mutation.Partition != "DC=example" || result.DestinationPartition != "DC=child,DC=example" ||
				!result.Mutation.PartialEffectsPossible || !result.Security.Complete || !result.Security.Delegated ||
				!result.Security.Protection.DelegationSent || result.Security.Protection.SASLProtection != admodel.SASLProtectionSeal ||
				result.Security.Protection.SASLCipherBits != 256 || !result.Security.Protection.MutualAuthentication {
				t.Fatalf("cross-domain result lost actual security, identity or possible effects: %+v, %v", result, err)
			}
			assertPortableMoveOutcome(t, fault, result, err)
			if fault == "lost-ack" || fault == "partial-destination" {
				// Explicit independent read only. Never retry the move or overwrite
				// the original uncertain/accepted result with reconciliation facts.
				directory.mu.Lock()
				directory.fault = ""
				directory.mu.Unlock()
				identity, identityErr := admodel.IdentityByGUID(result.Mutation.TargetGUID.String())
				if identityErr != nil {
					t.Fatal(identityErr)
				}
				reconciled, reconcileErr := destination.ResolveIdentity(t.Context(), identity, admodel.ResolveIdentityOptions{Partition: result.DestinationPartition})
				if reconcileErr != nil || reconciled.Object == nil || reconciled.Object.DistinguishedName != result.Mutation.TargetDN || directory.submits != 1 ||
					result.Mutation.Verified {
					t.Fatalf("independent reconciliation lost location or replayed mutation: %+v, %v", reconciled, reconcileErr)
				}
			}
			retire()
		})
	}
}

func TestPortableSameDomainMoveRemainsAvailableWithoutDelegation(t *testing.T) {
	source, _, directory, retire := newPortableMoveWireClients(t, "same-domain")
	request := directory.data.InternalRequest
	request.Destination = nil
	result, err := source.MoveObject(t.Context(), request)
	if err != nil || result.CrossDomain || result.Mutation.PartialEffectsPossible || !result.Mutation.Verified ||
		result.Mutation.State != admodel.ObjectWriteAccepted || result.Mutation.After == nil || directory.submits != 1 || len(directory.controls) != 0 || result.Security.Delegated {
		t.Fatalf("same-domain move unnecessarily required forwarding or used cross-domain semantics: %+v, %v", result, err)
	}
	retire()
}

func assertPortableMoveOutcome(t *testing.T, fault string, result admodel.ObjectMoveResult, err error) {
	t.Helper()
	switch fault {
	case "refused":
		var status *admodel.LDAPError
		if err == nil || !errors.As(err, &status) || status.Code != 50 || result.Mutation.State != admodel.ObjectWriteRejected || result.Mutation.Verified {
			t.Fatalf("real server refusal lost status or acknowledgement: %+v, %v", result.Mutation, err)
		}
	case "lost-ack":
		if err == nil || admodel.Classify(err) != admodel.ClassUncertain || result.Mutation.State != admodel.ObjectWriteUncertain ||
			result.Mutation.After != nil || result.Mutation.Verified {
			t.Fatalf("lost move response became success/refusal: %+v, %v", result.Mutation, err)
		}
	case "partial-destination":
		var status *admodel.LDAPError
		if !errors.Is(err, admodel.ErrObjectReadback) || !errors.As(err, &status) || status.Code != 50 || result.Mutation.State != admodel.ObjectWriteAccepted ||
			result.Mutation.Verified || result.Mutation.ReadbackComplete || len(result.Mutation.ReadbackCandidates) != 1 {
			t.Fatalf("partial destination proof lost accepted write or returned object: %+v, %v", result.Mutation, err)
		}
	default:
		if err != nil || result.Mutation.State != admodel.ObjectWriteAccepted || !result.Mutation.Verified || !result.Mutation.ReadbackComplete ||
			result.Mutation.After == nil || result.Mutation.After.DistinguishedName != result.Mutation.TargetDN {
			t.Fatalf("accepted move failed complete destination GUID proof: %+v, %v", result.Mutation, err)
		}
	}
}
