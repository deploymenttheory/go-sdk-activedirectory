package acceptance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortableRefusedTreeDeleteDoesNotConcealPossiblePartialEffects(t *testing.T) {
	for _, recursive := range []bool{false, true} {
		for _, code := range []int64{11, 50} {
			t.Run(fmt.Sprintf("recursive=%t-code=%d", recursive, code), func(t *testing.T) {
				portableCheckFailedDelete(t, recursive, code)
			})
		}
	}
}

func TestPortableTreeDeletePreflightFailuresHaveNoPartialEffects(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(fmt.Sprint("canceled=", canceled), func(t *testing.T) {
			steps := []portableLDAPStep{portableLDAPBind(0)}
			if !canceled {
				steps = append(steps, portableMutationRoot(), portableMutationObject(nil))
			}
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate, steps...)
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := ad.ErrObjectControlUnsupported
			if canceled {
				cancel()
				want = context.Canceled
			}
			identity, err := ad.IdentityByDN("CN=owned," + portableMutationDomain)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.DeleteObject(ctx, ad.DeleteObjectRequest{Identity: identity, Recursive: true})
			if !errors.Is(err, want) || result.State != ad.ObjectWriteNotAttempted || result.PartialEffectsPossible ||
				errors.Is(err, ad.ErrObjectDeletionIncomplete) || ad.IsUncertain(err) {
				t.Fatal("preflight failure invented a submitted tree operation", result, err)
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != int32(len(steps)) {
				t.Fatal("tree-delete preflight submitted or retried a write", wire.requests.Load())
			}
		})
	}
}

func portableCheckFailedDelete(t *testing.T, recursive bool, code int64) {
	t.Helper()
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portableMutationRoot(admodel.InternalObjectTreeDeleteControl), portableMutationObject(nil),
		func(connection net.Conn, request *ber.Packet) error {
			if request.Children[1].Tag != ldap.ApplicationDelRequest || (recursive && (len(request.Children) != 3 || len(request.Children[2].Children) != 1)) ||
				(!recursive && len(request.Children) != 2) {
				return fmt.Errorf("tree-delete fixture expected one explicit controlled delete")
			}
			if recursive {
				control := request.Children[2].Children[0]
				if len(control.Children) != 2 || control.Children[0].Value != admodel.InternalObjectTreeDeleteControl || control.Children[1].Value != true {
					return fmt.Errorf("tree-delete fixture lost criticality or introduced a control value")
				}
			}
			_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationDelResponse, code).Bytes())
			return err
		})
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.DeleteObject(t.Context(), admodel.DeleteObjectRequest{Identity: identity, Recursive: recursive})
	var status *admodel.LDAPError
	expectedClass := ad.ClassUnclassified
	if code == 50 {
		expectedClass = ad.ClassDenied
	}
	if recursive {
		expectedClass = ad.ClassUncertain
	}
	if !errors.As(err, &status) || status.Code != uint32(code) || ad.Classify(err) != expectedClass ||
		ad.IsUncertain(err) != recursive || ad.IsDenied(err) != (!recursive && code == 50) ||
		errors.Is(err, ad.ErrObjectDeletionIncomplete) != recursive ||
		result.State != ad.ObjectWriteRejected || result.PartialEffectsPossible != recursive || result.TargetGUID == nil || result.Before == nil || result.Verified {
		t.Fatal("tree-delete server refusal hid possible prior descendant effects", result, err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 4 {
		t.Fatal("refused tree deletion was replayed or followed by unrequested mutation", wire.requests.Load())
	}
}
