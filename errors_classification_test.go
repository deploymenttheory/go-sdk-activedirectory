package activedirectory

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// packageSentinelNames returns the name of every package-level variable in
// this package whose name begins with Err, read from the source rather than
// from a list, so the set cannot drift from what the package actually exports.
//
// Build constraints are deliberately ignored: a sentinel behind a constraint
// would still have to be classified, and referencing it from the unconstrained
// classification map would fail to build — which is the outcome wanted, not a
// gap to tolerate.
func packageSentinelNames(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	set := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(set, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				continue
			}
			for _, spec := range general.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, identifier := range value.Names {
					if strings.HasPrefix(identifier.Name, "Err") {
						names[identifier.Name] = name
					}
				}
			}
		}
	}
	if len(names) == 0 {
		t.Fatal("no exported sentinels were found; the source scan is broken, not the package")
	}
	return names
}

// classifiedSentinelNames returns the identifier of every map key in
// sentinelClasses, read from the source of the classification file itself. The
// map's keys are error values, so a runtime test can see how many there are
// but not which sentinels they were — and "the count matches" would pass with
// one sentinel classified twice and another not at all.
func classifiedSentinelNames(t *testing.T) map[string]bool {
	t.Helper()
	const source = "errors_classification.go"
	file, err := parser.ParseFile(token.NewFileSet(), source, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "sentinelClasses" {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatalf("%s: sentinelClasses is not a composite literal", source)
			}
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				identifier, ok := pair.Key.(*ast.Ident)
				if !ok {
					t.Fatalf("%s: a sentinelClasses key is not a plain identifier", source)
				}
				if names[identifier.Name] {
					t.Errorf("%s is classified twice", identifier.Name)
				}
				names[identifier.Name] = true
			}
		}
	}
	if len(names) == 0 {
		t.Fatalf("%s: no sentinelClasses keys were found", source)
	}
	return names
}

// This is the test the classification layer exists for. Without it a sentinel
// added to any area later classifies as ClassUnclassified, and a caller that
// used to act correctly on that condition silently stops — which is the defect
// being fixed, reintroduced. Both directions fail: an unclassified sentinel,
// and a classified name that is no longer a sentinel.
func TestEverySentinelIsClassified(t *testing.T) {
	declared := packageSentinelNames(t)
	classified := classifiedSentinelNames(t)
	for name, file := range declared {
		if !classified[name] {
			t.Errorf("%s (%s) has no ErrorClass; add it to sentinelClasses", name, file)
		}
	}
	for name := range classified {
		if _, ok := declared[name]; !ok {
			t.Errorf("sentinelClasses names %s, which is not a package-level sentinel", name)
		}
	}
	if !t.Failed() {
		t.Logf("%d sentinels, all classified", len(declared))
	}
}

// Every class must be reachable. A class no sentinel or status code produces
// is a promise to callers that nothing keeps, and a predicate that can only
// ever return false.
func TestEveryClassIsReachable(t *testing.T) {
	reached := map[ErrorClass]bool{}
	for _, class := range sentinelClasses {
		reached[class] = true
	}
	for _, class := range ldapStatusClasses {
		reached[class] = true
	}
	for _, class := range classPrecedence {
		if !reached[class] {
			t.Errorf("no sentinel or LDAP status produces %s", class)
		}
	}
}

// Precedence must list each class exactly once. A class missing from it is
// unreachable through Classify however many sentinels map to it, and a
// duplicate makes the order ambiguous to a reader.
func TestPrecedenceCoversEveryClassOnce(t *testing.T) {
	seen := map[ErrorClass]int{}
	for _, class := range classPrecedence {
		seen[class]++
	}
	for class, count := range seen {
		if count != 1 {
			t.Errorf("%s appears %d times in classPrecedence", class, count)
		}
	}
	if seen[ClassUnclassified] != 0 {
		t.Error("ClassUnclassified must not be in classPrecedence; it is the fallthrough")
	}
	// Every non-zero class value up to the last must be covered, so adding a
	// class without adding it to the precedence list fails here.
	for class := ClassUncertain; class <= classHighest; class++ {
		if seen[class] != 1 {
			t.Errorf("%s (%d) is not in classPrecedence", class, class)
		}
	}
}

// The precedence order is a safety claim, not a style choice, so the three
// orderings that carry consequences are pinned individually. If a future
// change reorders the list, these fail with the reason attached.
func TestPrecedenceProtectsTheDangerousDirections(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want ErrorClass
		why  string
	}{
		{
			"uncertain beats denied",
			errors.Join(ErrObjectWriteUncertain, ErrObjectWritePermission),
			ClassUncertain,
			"a write whose outcome is unknown must never be reported as a clean refusal",
		},
		{
			"uncertain beats not-found",
			errors.Join(ErrObjectWriteUncertain, ErrDirectoryObjectNotFound),
			ClassUncertain,
			"an absent readback after an accepted write is not a deletion",
		},
		{
			"uncertain beats incomplete",
			errors.Join(ErrObjectReadback, ErrIncompleteResult),
			ClassUncertain,
			"the readback being short is why the outcome is unknown",
		},
		{
			"denied beats not-found",
			errors.Join(ErrObjectWritePermission, ErrDirectoryObjectNotFound),
			ClassDenied,
			"a search omits objects the identity cannot read, so a denial can present as absence",
		},
		{
			"denied beats conflict",
			errors.Join(ErrObjectWritePermission, ErrObjectConcurrency),
			ClassDenied,
			"retrying a refused operation in a loop never succeeds",
		},
		{
			"transport beats incomplete",
			errors.Join(ErrClosed, ErrIncompleteResult),
			ClassTransport,
			"a dead session explains the short read",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.err); got != test.want {
				t.Fatalf("Classify = %s, want %s: %s", got, test.want, test.why)
			}
		})
	}
}

func TestClassifyUnrecognisedAndNil(t *testing.T) {
	if got := Classify(nil); got != ClassUnclassified {
		t.Errorf("Classify(nil) = %s, want unclassified", got)
	}
	if got := Classify(errors.New("something else entirely")); got != ClassUnclassified {
		t.Errorf("a foreign error classified as %s; it must not be claimed", got)
	}
	// Unclassified must not satisfy any predicate: a caller that checks each
	// in turn has to fall through to its own handling.
	foreign := fmt.Errorf("wrapped: %w", errors.New("foreign"))
	for name, predicate := range map[string]func(error) bool{
		"IsUncertain": IsUncertain, "IsDenied": IsDenied, "IsConflict": IsConflict,
		"IsAlreadyExists": IsAlreadyExists, "IsNotFound": IsNotFound,
		"IsUnsupported": IsUnsupported, "IsInvalidRequest": IsInvalidRequest,
		"IsTransport": IsTransport, "IsIncomplete": IsIncomplete,
		"IsUnverified": IsUnverified,
	} {
		if predicate(foreign) {
			t.Errorf("%s accepted a foreign error", name)
		}
		if predicate(nil) {
			t.Errorf("%s accepted nil", name)
		}
	}
}

// The classification must see a refusal that arrived only as a server status,
// with no sentinel joined, because that is how several paths report.
func TestClassifyReadsLDAPStatus(t *testing.T) {
	for _, test := range []struct {
		code uint32
		want ErrorClass
	}{
		{50, ClassDenied}, {32, ClassNotFound}, {68, ClassAlreadyExists},
		{53, ClassUnsupported}, {19, ClassInvalidRequest},
		// Observed unclassified in the first live mutation run: an undefined
		// attribute, and a value AD DS refuses as already present — which is
		// also how it reports a single-value constraint violation.
		{16, ClassInvalidRequest}, {17, ClassInvalidRequest},
		{20, ClassInvalidRequest}, {34, ClassInvalidRequest},
		{67, ClassInvalidRequest},
	} {
		err := fmt.Errorf("read failed: %w", &LDAPError{Operation: "Search", Code: test.code})
		if got := Classify(err); got != test.want {
			t.Errorf("LDAP status %d classified as %s, want %s", test.code, got, test.want)
		}
	}
	// A status the table does not name contributes nothing rather than a
	// guess, so the joined sentinel decides.
	unknown := errors.Join(ErrIncompleteResult, &LDAPError{Operation: "Search", Code: 4})
	if got := Classify(unknown); got != ClassIncomplete {
		t.Errorf("an unnamed status overrode the joined sentinel: got %s", got)
	}
}

// LDAP 20 means a value already exists, not an object. Confusing the two
// would send a caller down the adopt-the-existing-object path for what is
// actually a malformed attribute change.
func TestClassifyKeepsValueExistsApartFromObjectExists(t *testing.T) {
	value := fmt.Errorf("modify: %w", &LDAPError{Operation: "Modify", Code: 20})
	if got := Classify(value); got != ClassInvalidRequest {
		t.Errorf("LDAP 20 classified as %s, want invalid-request", got)
	}
	if IsAlreadyExists(value) {
		t.Error("a duplicate attribute value reported as an existing object")
	}
	object := fmt.Errorf("add: %w", &LDAPError{Operation: "Add", Code: 68})
	if !IsAlreadyExists(object) {
		t.Error("LDAP 68 no longer reports an existing object")
	}
}

// A status and a sentinel disagreeing must resolve through the same
// precedence as two sentinels, not by whichever was inspected first.
func TestClassifyRanksStatusAndSentinelTogether(t *testing.T) {
	err := errors.Join(ErrObjectWriteUncertain, &LDAPError{Operation: "Modify", Code: 50})
	if got := Classify(err); got != ClassUncertain {
		t.Fatalf("Classify = %s, want uncertain: status 50 must not demote an uncertain write", got)
	}
}

// Every class must print a distinct name: the strings reach artifacts and
// logs, where two classes sharing one would be indistinguishable.
func TestClassStringsAreDistinct(t *testing.T) {
	seen := map[string]ErrorClass{}
	for class := ClassUnclassified; class <= classHighest; class++ {
		text := class.String()
		if text == "" {
			t.Errorf("class %d has no name", class)
		}
		if other, ok := seen[text]; ok {
			t.Errorf("classes %d and %d both print %q", other, class, text)
		}
		seen[text] = class
	}
	if ErrorClass(200).String() != "unclassified" {
		t.Error("an out-of-range class must print as unclassified, not as a valid class")
	}
}

// The wrapper types in this package unwrap to sentinels, so classification has
// to hold through them rather than only on a bare sentinel.
func TestClassifyThroughPackageErrorTypes(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want ErrorClass
	}{
		{
			"DirectoryCapabilityError",
			&DirectoryCapabilityError{Operation: "read", Required: DirectoryADDS},
			ClassUnsupported,
		},
		{
			"SearchError",
			&SearchError{Returned: 3, Cause: ErrSearchReferences},
			ClassIncomplete,
		},
		{
			"DirectoryReadError",
			&DirectoryReadError{Operation: "read", Cause: ErrAttributeUnavailable},
			ClassIncomplete,
		},
		{
			"SearchError wrapping a denial",
			&SearchError{Returned: 0, Cause: ErrObjectWritePermission},
			ClassDenied,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Classify(test.err); got != test.want {
				t.Fatalf("Classify = %s, want %s", got, test.want)
			}
		})
	}
}

// LocalServiceAccountNativeError classifies itself through a custom Is method
// rather than by wrapping, which is why Classify tests each sentinel with
// errors.Is instead of walking the error tree once. A tree walk would miss
// this, so it is pinned.
func TestClassifyHonoursCustomIsMethods(t *testing.T) {
	denied := &LocalServiceAccountNativeError{Operation: "NetAddServiceAccount", Status: 0xc0000022}
	if got := Classify(denied); got != ClassDenied {
		t.Fatalf("Classify = %s, want denied: the custom Is method was not consulted", got)
	}
	other := &LocalServiceAccountNativeError{Operation: "NetAddServiceAccount", Status: 0xc0000001}
	if got := Classify(other); got != ClassUnclassified {
		t.Fatalf("Classify = %s, want unclassified: an unrelated NTSTATUS must not be claimed", got)
	}
}

// Each predicate must answer for exactly its own class, so a caller can check
// them in any order without two matching the same error.
func TestPredicatesAreMutuallyExclusive(t *testing.T) {
	predicates := map[ErrorClass]func(error) bool{
		ClassUncertain: IsUncertain, ClassDenied: IsDenied, ClassConflict: IsConflict,
		ClassAlreadyExists: IsAlreadyExists, ClassNotFound: IsNotFound,
		ClassUnsupported: IsUnsupported, ClassInvalidRequest: IsInvalidRequest,
		ClassTransport: IsTransport, ClassIncomplete: IsIncomplete,
		ClassUnverified: IsUnverified,
	}
	for _, class := range classPrecedence {
		if _, ok := predicates[class]; !ok {
			t.Fatalf("%s has no exported predicate", class)
		}
	}
	samples := map[ErrorClass]error{
		ClassUncertain: ErrObjectWriteUncertain, ClassDenied: ErrObjectWritePermission,
		ClassConflict: ErrObjectConcurrency, ClassAlreadyExists: ErrObjectAlreadyExists,
		ClassNotFound: ErrDirectoryObjectNotFound, ClassUnsupported: ErrUnsupported,
		ClassInvalidRequest: ErrInvalidIdentity, ClassTransport: ErrClosed,
		ClassIncomplete: ErrIncompleteResult, ClassUnverified: ErrObjectUnverifiable,
	}
	for class, sample := range samples {
		for other, predicate := range predicates {
			if got := predicate(sample); got != (class == other) {
				t.Errorf("%s predicate returned %v for a %s error", other, got, class)
			}
		}
	}
}
