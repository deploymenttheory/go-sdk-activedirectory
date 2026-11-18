package acceptance

import (
	"context"
	"errors"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	centralaccess "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/central_access"
)

func TestPortablePolicyFailurePreservesObservationsAndWriteOutcome(t *testing.T) {
	for _, mode := range []string{"denied", "lost", "malformed", "cancelled", "partial-preflight", "partial-readback"} {
		t.Run(mode, func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			dn := "CN=owned," + admodel.InternalCentralAccessParent(portablePolicyConfiguration, false)
			identity, err := admodel.IdentityByDN(dn)
			if err != nil {
				t.Fatal(err)
			}
			guid, err := admodel.GUIDFromBytes(make([]byte, 16))
			if err != nil {
				t.Fatal(err)
			}
			proposed := `D:(XA;;FR;;;WD;(@Resource.Department == "Finance"))`
			object := func(partial bool) portableLDAPStep {
				return portablePolicyObject(dn, "msAuthz-CentralAccessRule", map[string][][]byte{
					admodel.InternalCentralProposed: {[]byte(proposed)},
				}, partial)
			}
			steps := []portableLDAPStep{portableLDAPBind(0), portablePolicyRoot(), portablePolicyRoot(), object(mode == "partial-preflight")}
			received := make(chan struct{})
			if mode != "partial-preflight" {
				steps = append(steps, func(connection net.Conn, request *ber.Packet) error {
					if err := portablePolicyModify(request, guid, []portablePolicyChange{{2, admodel.InternalCentralProposed, []byte(proposed)}}); err != nil {
						return err
					}
					close(received)
					return portableReaderWriteResponse(connection, request, mode)
				})
			}
			if mode == "partial-readback" {
				steps = append(steps, object(true))
			}
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			session, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				go func() {
					select {
					case <-received:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			result, err := centralaccess.New(client).UpdateCentralAccessRule(ctx, admodel.UpdateCentralAccessRuleRequest{
				Identity: identity, ProposedACL: &proposed,
			})
			portableCheckPolicyFailure(t, mode, result.Mutation, err)
			if mode == "lost" || mode == "malformed" || mode == "cancelled" {
				attempt := session.(admodel.InternalLdapWriteSession).InternalLdapWrite(t.Context(), admodel.InternalLdapWriteRequest{
					InternalOperation: admodel.InternalLdapWriteDelete, InternalDn: admodel.InternalObjectGUIDTarget(guid),
				})
				if attempt.State != admodel.InternalLdapWriteNotAttempted || !errors.Is(attempt.Err, admodel.ErrClosed) {
					t.Fatal("interrupted policy session permitted another mutation", attempt)
				}
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != int32(len(steps)) {
				t.Fatal("policy update was retried or a refused write was read back", wire.requests.Load())
			}
		})
	}
}

func portableCheckPolicyFailure(t *testing.T, mode string, mutation admodel.ObjectMutationResult, err error) {
	t.Helper()
	if err == nil || mutation.Verified {
		t.Fatal("failed policy operation was reported as verified", mutation, err)
	}
	switch mode {
	case "partial-preflight":
		if mutation.State != admodel.ObjectWriteNotAttempted || mutation.Before != nil || len(mutation.PreflightCandidates) != 1 ||
			!errors.Is(err, admodel.ErrIncompleteResult) {
			t.Fatal("partial preflight lost its entry or permitted mutation", mutation, err)
		}
	case "partial-readback":
		if mutation.State != admodel.ObjectWriteAccepted || len(mutation.ReadbackCandidates) != 1 ||
			!errors.Is(err, admodel.ErrObjectReadback) {
			t.Fatal("accepted policy write or partial observation was lost", mutation, err)
		}
	case "denied":
		var response *admodel.LDAPError
		if mutation.State != admodel.ObjectWriteRejected || !errors.Is(err, admodel.ErrObjectWritePermission) ||
			!errors.As(err, &response) || response.Code != 50 {
			t.Fatal("actual policy refusal lost its server status", mutation, err)
		}
	default:
		if mutation.State != admodel.ObjectWriteUncertain || !errors.Is(err, admodel.ErrObjectWriteUncertain) || mutation.Before == nil {
			t.Fatal("submitted interrupted policy update did not remain uncertain", mutation, err)
		}
	}
}
