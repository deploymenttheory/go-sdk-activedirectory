// Command errorclassification shows how to turn an error from this SDK into
// the one decision a caller has to make about it.
//
// It contacts no directory and needs no Windows: every error below is
// constructed, including the joined ones, so the precedence rules are visible
// as output rather than described. Run it anywhere.
package main

import (
	"errors"
	"fmt"

	ad "github.com/deploymenttheory/go-sdk-activedirectory"
)

// handle is the shape a caller that tracks directory state wants: one switch
// over the class, not a chain of errors.Is against a hundred sentinels. The
// sentinel is still what belongs in the message.
func handle(operation string, err error) string {
	switch ad.Classify(err) {
	case ad.ClassUncertain:
		return "re-read the target before anything else; record neither applied nor absent"
	case ad.ClassDenied:
		return "stop and report the permission; retrying cannot succeed"
	case ad.ClassConflict:
		return "re-read and retry; nothing was written"
	case ad.ClassAlreadyExists:
		return "adopt the existing object instead of creating it"
	case ad.ClassNotFound:
		return "treat the object as absent"
	case ad.ClassUnsupported:
		return "stop and report what the directory would need to be"
	case ad.ClassInvalidRequest:
		return "correct the request; retrying it unchanged cannot succeed"
	case ad.ClassTransport:
		return "retry the read on a new session"
	case ad.ClassIncomplete:
		return "use what arrived, but do not read its gaps as absence"
	case ad.ClassUnverified:
		return "record it as applied; the SDK could not prove the effect"
	case ad.ClassUnclassified:
		return "a failure this SDK did not produce; handle it yourself"
	}
	return fmt.Sprintf("unreachable class for %s", operation)
}

func main() {
	cases := []struct {
		what string
		err  error
	}{
		{"a read of an object that is not there", ad.ErrDirectoryObjectNotFound},
		{"a create whose object exists", ad.ErrObjectAlreadyExists},
		{"a write the identity may not make", ad.ErrObjectWritePermission},
		{"a failed version precondition", ad.ErrObjectConcurrency},
		{"an identity of the wrong class", ad.ErrNotGroup},
		{"an operation this directory type lacks", ad.ErrUnsupportedDirectory},
		{"a closed client", ad.ErrClosed},

		// The two that matter most, and the reason a class beats a name.
		{
			"a write accepted but not confirmed",
			errors.Join(ad.ErrObjectWriteUncertain, ad.ErrIncompleteResult),
		},
		{
			"a denial that also reported no object",
			errors.Join(ad.ErrObjectWritePermission, ad.ErrDirectoryObjectNotFound),
		},

		// A refusal that arrived only as a server status, with no sentinel.
		{
			"LDAP status 50 alone",
			fmt.Errorf("modify failed: %w", &ad.LDAPError{Operation: "Modify", Code: 50}),
		},

		// A real search that found objects and left one partition unsearched.
		{
			"a search that returned a continuation reference",
			&ad.SearchError{Returned: 51, Cause: ad.ErrSearchReferences},
		},

		// The ordinary outcome of clearing an attribute: accepted, and
		// unprovable because an absence cannot tell success from denied
		// visibility. It must not report as uncertain.
		{"an attribute clear", ad.ErrObjectUnverifiable},

		{"an error from somewhere else", errors.New("connection reset by peer")},
	}

	for _, test := range cases {
		class := ad.Classify(test.err)
		fmt.Printf("%-48s %-16s %s\n", test.what, class, handle(test.what, test.err))
	}

	fmt.Println()

	// Two cases deserve spelling out, because getting either wrong is how a
	// caller corrupts the state it is tracking.
	uncertain := errors.Join(ad.ErrObjectWriteUncertain, ad.ErrDirectoryObjectNotFound)
	fmt.Printf("uncertain + not-found  -> %s\n", ad.Classify(uncertain))
	fmt.Println("  The readback found nothing, but the write was accepted. Treating this")
	fmt.Println("  as a deletion would discard an object the directory may well hold.")
	fmt.Printf("  IsNotFound says %v, which is what makes that mistake unavailable.\n",
		ad.IsNotFound(uncertain))

	denied := errors.Join(ad.ErrObjectWritePermission, ad.ErrDirectoryObjectNotFound)
	fmt.Printf("\ndenied + not-found     -> %s\n", ad.Classify(denied))
	fmt.Println("  An Active Directory search omits objects the bound identity cannot")
	fmt.Println("  read, so a permissions change can present as an absence.")
	fmt.Printf("  IsNotFound says %v here too.\n", ad.IsNotFound(denied))

	fmt.Println()

	// The class does not replace the sentinel. It decides control flow; the
	// sentinel is what the operator needs to read.
	err := &ad.SearchError{Returned: 51, Cause: ad.ErrSearchReferences}
	if ad.IsIncomplete(err) && errors.Is(err, ad.ErrSearchReferences) {
		var search *ad.SearchError
		if errors.As(err, &search) {
			fmt.Printf("incomplete, specifically: %d objects arrived and one subordinate\n",
				search.Returned)
			fmt.Println("naming context went unsearched. A caller asking a narrower")
			fmt.Println("question may accept that; one enumerating a subtree may not.")
		}
	}
}
