package acceptance

import (
	"context"
	"errors"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
	adservice_replication "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

// A site change is several object writes. When one of them fails after earlier
// ones were accepted, the directory holds part of the change — and before this
// was fixed the returned error said nothing about it. A refused third write
// reported as plain access denied, which reads as though the whole change was
// rejected, so a caller tracking state recorded nothing and the two objects
// already created became invisible to it.
//
// The step results always held the truth. The point of these tests is that a
// caller does not have to know to walk them: one classification of the
// returned error is enough.
func TestSitePartialWriteReachesTheReturnedError(t *testing.T) {
	for _, test := range []struct {
		InternalName  string
		InternalState admodel.InternalLdapWriteState
		InternalCode  uint32
		// The class before the fix, recorded to show what changed and to make
		// a regression obvious rather than merely red.
		InternalPreviously admodel.ErrorClass
	}{
		{"refused after two accepted writes", admodel.InternalLdapWriteRejected, 50, admodel.ClassDenied},
		{"uncertain after two accepted writes", admodel.InternalLdapWriteUncertain, 50, admodel.ClassUncertain},
		{"refused for a constraint rather than a permission", admodel.InternalLdapWriteRejected, 19, admodel.ClassInvalidRequest},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			client, session := InternalNewTopologyTestClient(t, false)
			session.InternalFailAt = 3
			session.InternalFailure = admodel.InternalLdapWriteAttempt{
				State: test.InternalState,
				Err:   &admodel.LDAPError{Code: test.InternalCode},
			}

			result, err := adservice_replication.New(client).
				CreateReplicationSite(context.Background(), admodel.CreateReplicationSiteRequest{Name: "Partial"})
			if err == nil {
				t.Fatal("the create succeeded; this test needs the third write to fail")
			}

			// The premise: two writes landed before the failure.
			if len(result.Steps) != 3 {
				t.Fatalf("got %d steps, want 3", len(result.Steps))
			}
			accepted := 0
			for _, step := range result.Steps {
				if step.Mutation.State == admodel.ObjectWriteAccepted {
					accepted++
				}
			}
			if accepted != 2 {
				t.Fatalf("%d steps were accepted, want 2; the fixture no longer "+
					"reproduces a partial write", accepted)
			}

			if !errors.Is(err, admodel.ErrReplicationTopologyIncomplete) {
				t.Errorf("the error does not report an incomplete change: %v", err)
			}
			if got := admodel.Classify(err); got != admodel.ClassUncertain {
				t.Errorf("Classify = %s, want uncertain (it was %s before the fix): %v",
					got, test.InternalPreviously, err)
			}
			// The underlying failure must survive, or a caller loses the reason.
			var ldapErr *admodel.LDAPError
			if !errors.As(err, &ldapErr) || ldapErr.Code != test.InternalCode {
				t.Errorf("the originating LDAP status was lost from %v", err)
			}
		})
	}
}

// The sentinel must mean "part of this landed", so it must be absent whenever
// nothing did. Without this, it would degrade into a second name for failure
// and a caller would reconcile after every refused call.
func TestSiteFailureBeforeAnyWriteIsNotReportedAsPartial(t *testing.T) {
	t.Run("the first write is refused", func(t *testing.T) {
		client, session := InternalNewTopologyTestClient(t, false)
		session.InternalFailAt = 1
		session.InternalFailure = admodel.InternalLdapWriteAttempt{
			State: admodel.InternalLdapWriteRejected,
			Err:   &admodel.LDAPError{Code: 50},
		}
		result, err := adservice_replication.New(client).
			CreateReplicationSite(context.Background(), admodel.CreateReplicationSiteRequest{Name: "Refused"})
		if err == nil {
			t.Fatal("the create succeeded")
		}
		for _, step := range result.Steps {
			if step.Mutation.State == admodel.ObjectWriteAccepted {
				t.Fatal("a write was accepted; this case needs none to be")
			}
		}
		if errors.Is(err, admodel.ErrReplicationTopologyIncomplete) {
			t.Errorf("a wholly refused change was reported as partial: %v", err)
		}
		if got := admodel.Classify(err); got != admodel.ClassDenied {
			t.Errorf("Classify = %s, want denied: nothing landed, so the refusal "+
				"is the whole story", got)
		}
	})

	t.Run("the request is refused before any write is attempted", func(t *testing.T) {
		client, session := InternalNewTopologyTestClient(t, false)
		_, err := adservice_replication.New(client).
			CreateReplicationSite(context.Background(), admodel.CreateReplicationSiteRequest{Name: ""})
		if !errors.Is(err, admodel.ErrReplicationTopology) {
			t.Fatalf("got %v, want a topology input refusal", err)
		}
		if len(session.InternalWrites) != 0 {
			t.Fatalf("%d writes were submitted for an invalid request", len(session.InternalWrites))
		}
		if errors.Is(err, admodel.ErrReplicationTopologyIncomplete) {
			t.Error("an input refusal was reported as a partial change")
		}
		if got := admodel.Classify(err); got != admodel.ClassInvalidRequest {
			t.Errorf("Classify = %s, want invalid-request", got)
		}
	})
}

// A completed change must not be reported as partial either, which is the
// other way the sentinel could become noise.
func TestSuccessfulSiteChangeIsNotReportedAsPartial(t *testing.T) {
	client, _ := InternalNewTopologyTestClient(t, false)
	result, err := adservice_replication.New(client).
		CreateReplicationSite(context.Background(), admodel.CreateReplicationSiteRequest{Name: "Complete"})
	if err != nil {
		t.Fatalf("the create failed: %v", err)
	}
	if !result.Complete {
		t.Fatal("the create did not report complete")
	}
	if admodel.Classify(err) != admodel.ClassUnclassified {
		t.Errorf("a successful change classified as %s", admodel.Classify(err))
	}
}

// Update and Delete run the same stepped sequence, so they carry the same
// hazard and are wired through the same guard. Without this, a later change
// could leave either of them reporting a partial write as a clean refusal.
func TestSiteUpdateAndDeleteAlsoReportPartialWrites(t *testing.T) {
	t.Run("delete refused partway through its children", func(t *testing.T) {
		client, session := InternalNewTopologyTestClient(t, false)
		// The site must have a recognized administrative child so the delete
		// takes more than one write; the settings object is created with it.
		identity := InternalTopologyTestIdentity(InternalTopologyTestSiteB)
		session.InternalFailAt = 2
		session.InternalFailure = admodel.InternalLdapWriteAttempt{
			State: admodel.InternalLdapWriteRejected,
			Err:   &admodel.LDAPError{Code: 50},
		}
		result, err := adservice_replication.New(client).
			DeleteReplicationSite(context.Background(), identity, admodel.ObjectMutationOptions{})
		if err == nil {
			t.Fatal("the delete succeeded; this test needs its second write to fail")
		}
		accepted := false
		for _, step := range result.Steps {
			if step.Mutation.State == admodel.ObjectWriteAccepted {
				accepted = true
			}
		}
		if !accepted {
			t.Fatalf("no write was accepted before the failure, so this no longer "+
				"reproduces a partial delete: %v", err)
		}
		if !errors.Is(err, admodel.ErrReplicationTopologyIncomplete) {
			t.Errorf("a partial delete was not reported as incomplete: %v", err)
		}
		if got := admodel.Classify(err); got != admodel.ClassUncertain {
			t.Errorf("Classify = %s, want uncertain", got)
		}
	})
}
