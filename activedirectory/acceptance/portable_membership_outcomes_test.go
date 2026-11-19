package acceptance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	memberships "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/memberships"
)

func TestPortablePrincipalMembershipRetainsIndependentWriteOutcomes(t *testing.T) {
	for _, mode := range []string{"complete", "denied", "lost", "malformed", "partial-read", "cancel-before", "cancel-after-accepted"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cause := errors.New("owned batch cancellation")
			principal := InternalMembershipObject("principal", portableMutationDomain, "user", 1, 1100, 1)
			groups := []admodel.Object{
				InternalMembershipObject("first", portableMutationDomain, "group", 2, 1101, 1),
				InternalMembershipObject("second", portableMutationDomain, "group", 3, 1102, 1),
			}
			steps := portableMembershipBatchSteps(mode, principal, groups, func() { cancel(cause) })
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			if mode == "cancel-before" {
				cancel(cause)
			}
			result, err := memberships.New(client).AddPrincipalGroupMembership(ctx, memberships.PrincipalGroupMembershipRequest{
				Principal: InternalGroupMemberDN(t, principal.DistinguishedName),
				Groups: []memberships.PrincipalMembershipTarget{
					{Identity: InternalGroupMemberDN(t, groups[0].DistinguishedName)}, {Identity: InternalGroupMemberDN(t, groups[1].DistinguishedName)},
				}, Mode: memberships.GroupMembershipStrict,
			})
			if result.Mutation.TargetGUID != nil || result.Mutation.TargetDN != "" || result.Mutation.Before != nil || result.Mutation.After != nil ||
				result.Mutation.Verified || len(result.Outcomes) != 2 {
				t.Fatal("batch invented a single target, observation or linked-edge verification", result, err)
			}
			requests := int32(10)
			switch mode {
			case "complete":
				requests = 11
				if err != nil || !result.Complete || result.Processed != 2 || result.Mutation.State != admodel.ObjectWriteAccepted || result.Mutation.PartialEffectsPossible {
					t.Fatal("completed independent batch lost its accepted outcomes", result, err)
				}
			case "cancel-before":
				requests = 1
				if !errors.Is(err, cause) || result.Processed != 0 || result.Mutation.State != admodel.ObjectWriteNotAttempted ||
					result.Mutation.PartialEffectsPossible || errors.Is(err, memberships.ErrPrincipalMembershipIncomplete) {
					t.Fatal("pre-write cancellation manufactured an effect", result, err)
				}
			case "cancel-after-accepted":
				requests = 7
				if !errors.Is(err, cause) || result.Processed != 1 || result.Outcomes[1].Result.Mutation.State != admodel.ObjectWriteNotAttempted {
					t.Fatal("cancellation lost its cause or advanced to another group", result, err)
				}
			case "denied", "partial-read":
				var status *admodel.LDAPError
				if !errors.As(err, &status) || status.Code != 50 || result.Outcomes[1].Result.Mutation.State != admodel.ObjectWriteRejected {
					t.Fatal("batch hid an actual server denial", result, err)
				}
				if mode == "partial-read" && (len(result.Outcomes[0].Result.Mutation.ReadbackCandidates) != 1 || result.Outcomes[0].Result.Mutation.ReadbackComplete) {
					t.Fatal("partial accepted-stage readback was discarded or counted as complete", result, err)
				}
			case "lost", "malformed":
				if result.Outcomes[1].Result.Mutation.State != admodel.ObjectWriteUncertain || result.Mutation.State != admodel.ObjectWriteUncertain ||
					!errors.Is(err, admodel.ErrObjectWriteUncertain) {
					t.Fatal("submitted second write was reported as rejected or not attempted", result, err)
				}
			}
			if mode != "complete" && mode != "cancel-before" {
				if result.Complete || admodel.Classify(err) != admodel.ClassUncertain || !errors.Is(err, memberships.ErrPrincipalMembershipIncomplete) ||
					!result.Mutation.PartialEffectsPossible || result.Outcomes[0].Result.Mutation.State != admodel.ObjectWriteAccepted {
					t.Fatal("incomplete sequence erased the earlier acknowledged change", result, err)
				}
			}
			if mode != "cancel-before" {
				for i := range result.Processed {
					if result.Outcomes[i].Result.Mutation.TargetGUID == nil || result.Outcomes[i].Result.Mutation.Before == nil ||
						result.Outcomes[i].Result.Mutation.TargetDN != groups[i].DistinguishedName {
						t.Fatal("per-group stable identity was lost", result, err)
					}
				}
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != requests {
				t.Fatal("batch replayed a write or advanced after unknown/canceled outcome", wire.requests.Load(), requests)
			}
		})
	}
}

func portableMembershipBatchSteps(mode string, principal admodel.Object, groups []admodel.Object, cancel func()) []portableLDAPStep {
	steps := []portableLDAPStep{portableLDAPBind(0)}
	if mode == "cancel-before" {
		return steps
	}
	steps = append(steps, portableMutationRoot(), portableMembershipObject(principal, false))
	for i, group := range groups {
		steps = append(steps, portableMutationRoot(), portableMembershipObject(group, false),
			func(connection net.Conn, request *ber.Packet) error {
				protocol := request.Children[1]
				if protocol.Tag != ldap.ApplicationModifyRequest || protocol.Children[0].Value != InternalMembershipObjectKey(group) || len(request.Children) != 2 {
					return fmt.Errorf("batch fixture expected one strict GUID-addressed Modify without fallback controls")
				}
				change := protocol.Children[1].Children[0]
				if len(protocol.Children[1].Children) != 1 || change.Children[0].Value != int64(0) || change.Children[1].Children[0].Value != "member" ||
					string(change.Children[1].Children[1].Children[0].Data.Bytes()) != InternalMembershipObjectKey(principal) {
					return fmt.Errorf("batch fixture saw changed member intent or more than one mutation")
				}
				if i == 1 && (mode == "lost" || mode == "malformed") {
					if mode == "lost" {
						return connection.Close()
					}
					response := portableMutationMalformedResult(request, ldap.ApplicationModifyResponse)
					_, err := connection.Write(response.Bytes())
					return err
				}
				code := int64(0)
				if i == 1 && (mode == "denied" || mode == "partial-read") {
					code = 50
				}
				_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationModifyResponse, code).Bytes())
				return err
			})
		if i == 1 && mode != "complete" {
			break
		}
		readback := portableMembershipObject(group, mode == "partial-read")
		steps = append(steps, func(connection net.Conn, request *ber.Packet) error {
			if mode == "cancel-after-accepted" {
				cancel()
				return nil
			}
			return readback(connection, request)
		})
		if mode == "cancel-after-accepted" {
			break
		}
	}
	return steps
}

func portableMembershipObject(object admodel.Object, partial bool) portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		protocol := request.Children[1]
		if protocol.Tag != ldap.ApplicationSearchRequest {
			return fmt.Errorf("batch fixture expected identity observation")
		}
		value, valueErr := object.Values("objectGUID").Single()
		filter, err := ldap.CompileFilter("(objectGUID=" + admodel.InternalIdentityBinaryLiteral(value.Bytes()) + ")")
		if err != nil || valueErr != nil ||
			(protocol.Children[0].Value != object.DistinguishedName && (protocol.Children[0].Value != portableMutationDomain ||
				!bytes.Equal(protocol.Children[6].Bytes(), filter.Bytes()))) {
			return fmt.Errorf("batch fixture expected the exact resolved principal or group")
		}
		return portableReaderSearchResponse(connection, request, object.DistinguishedName, object.Attributes, true, partial)
	}
}
