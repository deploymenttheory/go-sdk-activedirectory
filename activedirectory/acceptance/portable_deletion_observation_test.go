package acceptance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"

	ldap "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/ldap/v3"
	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

func TestPortablePostDeleteOmissionCannotVerifyDeletion(t *testing.T) {
	certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
	wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
		portableLDAPBind(0), portableMutationRoot(), portableMutationObject(nil), portableDeletionAccepted(), portableDeletionEmptySearch())
	_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
	identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.DeleteObject(t.Context(), admodel.DeleteObjectRequest{Identity: identity})
	if !errors.Is(err, admodel.ErrObjectUnverifiable) || admodel.Classify(err) != admodel.ClassUnverified ||
		result.State != admodel.ObjectWriteAccepted || result.TargetGUID == nil || result.Before == nil ||
		result.Verified || !result.AbsentAfter || result.After != nil {
		t.Fatal("ordinary empty post-delete search was treated as proof of deletion", result, err)
	}
	_ = client.Close()
	wire.wait(t)
	if wire.requests.Load() != 5 {
		t.Fatal("deletion was retried or unsupported controls were attempted", wire.requests.Load())
	}
}

func TestPortableDeleteCanBeVerifiedByAnExplicitDeletedGUIDObservation(t *testing.T) {
	for _, oid := range []string{admodel.InternalObjectShowDeletedControl, admodel.InternalObjectShowRecycledControl} {
		t.Run(oid, func(t *testing.T) {
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
				portableLDAPBind(0), portableMutationRoot(oid), portableMutationObject(nil), portableDeletionAccepted(), portableDeletionEmptySearch(),
				func(connection net.Conn, request *ber.Packet) error {
					if err := portableDeletionCheckProofRequest(request, oid); err != nil {
						return err
					}
					attributes := map[string][][]byte{"objectGUID": {make([]byte, 16)}, "isDeleted": {[]byte("TRUE")}, "objectClass": {[]byte("user")}}
					if oid == admodel.InternalObjectShowRecycledControl {
						attributes["isRecycled"] = [][]byte{[]byte("TRUE")}
					}
					return portableReaderSearchResponse(connection, request,
						`CN=owned\0ADEL:00000000-0000-0000-0000-000000000000,CN=Deleted Objects,`+portableMutationDomain,
						attributes, true, false)
				})
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.DeleteObject(t.Context(), admodel.DeleteObjectRequest{Identity: identity})
			if err != nil || result.State != admodel.ObjectWriteAccepted || !result.Verified || !result.AbsentAfter || result.TargetGUID == nil || result.After != nil ||
				result.DeletionReadback == nil || !result.DeletionReadback.Complete || len(result.DeletionReadback.Objects) != 1 {
				t.Fatal("explicit same-GUID deleted-object proof did not verify the accepted deletion", result, err)
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != 6 {
				t.Fatal("deletion was replayed or its positive proof skipped", wire.requests.Load())
			}
		})
	}
}

func portableDeletionCheckProofRequest(request *ber.Packet, oid string) error {
	if len(request.Children) != 3 || request.Children[1].Tag != ldap.ApplicationSearchRequest ||
		request.Children[1].Children[0].Value != portableMutationDomain || request.Children[1].Children[1].Value != int64(ldap.ScopeWholeSubtree) {
		return fmt.Errorf("deleted-object proof lost its original naming context or controlled search")
	}
	filter, err := ldap.DecompileFilter(request.Children[1].Children[6])
	if err != nil || filter != "(&(objectGUID="+strings.Repeat(`\00`, 16)+")(isDeleted=TRUE))" {
		return fmt.Errorf("deleted-object proof was not bounded to the known GUID and deleted state")
	}
	matched := false
	for _, control := range request.Children[2].Children {
		if control.Children[0].Value == ldap.ControlTypePaging {
			continue
		}
		if matched || len(control.Children) != 2 || control.Children[0].Value != oid || control.Children[1].Value != true {
			return fmt.Errorf("deleted-object proof control was noncritical, changed or had a value")
		}
		matched = true
	}
	if !matched {
		return fmt.Errorf("deleted-object visibility control was missing")
	}
	return nil
}

func portableDeletionAccepted() portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if len(request.Children) != 2 || request.Children[1].Tag != ldap.ApplicationDelRequest ||
			string(request.Children[1].Data.Bytes()) != "<GUID=00000000000000000000000000000000>" {
			return fmt.Errorf("delete fixture expected one exact GUID-addressed leaf request")
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationDelResponse, 0).Bytes())
		return err
	}
}

func TestPortableDeletionProofFailuresPreserveTheAcceptedWrite(t *testing.T) {
	for _, name := range []string{"empty", "refused", "partial-denied", "wrong-guid", "live-state", "missing-state", "out-of-scope", "malformed", "lost", "canceled"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(t.Context())
			defer cancel(nil)
			cause := errors.New("owned deletion proof cancellation")
			certificate, roots := portableTLSCertificate(t, portableTLSHost, false, false)
			wire := newPortableLDAPWire(t, admodel.TransportLDAPS, certificate,
				portableLDAPBind(0), portableMutationRoot(admodel.InternalObjectShowDeletedControl, admodel.InternalObjectShowRecycledControl),
				portableMutationObject(nil), portableDeletionAccepted(), portableDeletionEmptySearch(),
				func(connection net.Conn, request *ber.Packet) error {
					if err := portableDeletionCheckProofRequest(request, admodel.InternalObjectShowRecycledControl); err != nil {
						return err
					}
					return portableDeletionFault(connection, request, name, func() { cancel(cause) })
				})
			_, client := portableLDAPSession(t, portableTLSConfig(admodel.TransportLDAPS, roots), wire)
			identity, err := admodel.IdentityByDN("CN=owned," + portableMutationDomain)
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.DeleteObject(ctx, admodel.DeleteObjectRequest{Identity: identity})
			if err == nil || result.State != admodel.ObjectWriteAccepted || result.TargetGUID == nil || result.Before == nil ||
				result.Verified || !result.AbsentAfter || !result.ReadbackComplete || result.After != nil || result.DeletionReadback == nil {
				t.Fatal("failed deleted-object proof hid the accepted write or fabricated verification", result, err)
			}
			if name == "empty" {
				if !errors.Is(err, admodel.ErrObjectUnverifiable) || admodel.Classify(err) != admodel.ClassUnverified || !result.DeletionReadback.Complete {
					t.Fatal("empty controlled search was not explicitly unverified", result, err)
				}
			} else if !errors.Is(err, admodel.ErrObjectReadback) || admodel.Classify(err) != admodel.ClassUncertain {
				t.Fatal("failed proof lost its uncertain readback classification", result, err)
			}
			if name == "partial-denied" && (len(result.DeletionReadback.Objects) != 1 || result.DeletionReadback.Complete) {
				t.Fatal("partial tombstone observation was discarded or treated as complete", result, err)
			}
			if name == "refused" || name == "partial-denied" {
				code := uint32(12)
				if name == "partial-denied" {
					code = 50
				}
				var operation *admodel.LDAPError
				if !errors.As(err, &operation) || operation.Code != code {
					t.Fatal("actual deleted-object search refusal was lost", err)
				}
			}
			if name == "malformed" || name == "lost" || name == "canceled" {
				if name == "canceled" && !errors.Is(err, cause) {
					t.Fatal("accepted deletion lost the original cancellation cause", err)
				}
				next, nextErr := client.UpdateObject(t.Context(), admodel.UpdateObjectRequest{Identity: identity, Changes: []admodel.AttributeChange{{
					Attribute: "description", Kind: admodel.AttributeSet, Values: []admodel.RawValue{admodel.NewRawValue([]byte("never-submitted"))},
				}}})
				if !errors.Is(nextErr, admodel.ErrClosed) || next.State != admodel.ObjectWriteNotAttempted {
					t.Fatal("failed proof session was reused for another write", next, nextErr)
				}
			}
			_ = client.Close()
			wire.wait(t)
			if wire.requests.Load() != 6 {
				t.Fatal("accepted delete or refused visibility control was retried", wire.requests.Load())
			}
		})
	}
}

func portableDeletionFault(connection net.Conn, request *ber.Packet, name string, cancel func()) error {
	attributes := map[string][][]byte{"objectGUID": {make([]byte, 16)}, "isDeleted": {[]byte("TRUE")}}
	dn := `CN=owned\0ADEL:00000000-0000-0000-0000-000000000000,CN=Deleted Objects,` + portableMutationDomain
	switch name {
	case "empty":
		return portableDeletionEmptySearch()(connection, request)
	case "refused":
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 12).Bytes())
		return err
	case "wrong-guid":
		attributes["objectGUID"][0][0] = 1
	case "live-state":
		attributes["isDeleted"] = [][]byte{[]byte("FALSE")}
	case "missing-state":
		delete(attributes, "isDeleted")
	case "out-of-scope":
		dn = "CN=deleted,DC=foreign,DC=test"
	case "malformed":
		response := portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0)
		response.Children[1].Children[1] = ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, "")
		_, err := connection.Write(response.Bytes())
		return err
	case "lost":
		return connection.Close()
	case "canceled":
		cancel()
		return nil
	}
	return portableReaderSearchResponse(connection, request, dn, attributes, true, name == "partial-denied")
}

func portableDeletionEmptySearch() portableLDAPStep {
	return func(connection net.Conn, request *ber.Packet) error {
		if request.Children[1].Tag != ldap.ApplicationSearchRequest {
			return fmt.Errorf("deletion fixture expected a read without replay")
		}
		if _, _, err := portableLDAPPaging(request); err != nil {
			return err
		}
		_, err := connection.Write(portableLDAPResult(request, ldap.ApplicationSearchResultDone, 0, &ldap.ControlPaging{}).Bytes())
		return err
	}
}
