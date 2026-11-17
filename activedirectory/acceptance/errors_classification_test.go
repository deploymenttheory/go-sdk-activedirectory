package acceptance

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// packageSentinelNames returns the name of every package-level variable in
// the implementation packages whose name begins with Err, read from source rather than
// from a list, so the set cannot drift from what the package actually exports.
//
// Build constraints are deliberately ignored: a sentinel behind a constraint
// would still have to be classified, and referencing it from the unconstrained
// classification map would fail to build — which is the outcome wanted, not a
// gap to tolerate.
func InternalPackageSentinelNames(t *testing.T) map[string]string {
	t.Helper()
	names := map[string]string{}
	set := token.NewFileSet()
	root := repositoryFile("activedirectory")
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "acceptance" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(set, name, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
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
				for i, identifier := range value.Names {
					if strings.HasPrefix(identifier.Name, "Err") {
						// Public packages project the original sentinel identities.
						// Count their declaration, not each re-exported alias.
						if i < len(value.Values) {
							if alias, ok := value.Values[i].(*ast.SelectorExpr); ok &&
								alias.Sel.Name == identifier.Name {
								continue
							}
						}
						if previous, exists := names[identifier.Name]; exists {
							t.Fatalf(
								"sentinel %s declared in both %s and %s",
								identifier.Name,
								previous,
								name,
							)
						}
						names[identifier.Name] = name
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
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
func InternalClassifiedSentinelNames(t *testing.T) map[string]bool {
	t.Helper()
	source := repositoryFile("activedirectory/internal/model/errors_classification.go")
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
			if !ok || len(value.Names) != 1 || value.Names[0].Name != "InternalSentinelClasses" {
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
				var name string
				switch key := pair.Key.(type) {
				case *ast.Ident:
					name = key.Name
				case *ast.SelectorExpr:
					name = key.Sel.Name
				default:
					t.Fatalf("%s: a sentinelClasses key is not a sentinel identifier", source)
				}
				if names[name] {
					t.Errorf("%s is classified twice", name)
				}
				names[name] = true
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
	declared := InternalPackageSentinelNames(t)
	classified := InternalClassifiedSentinelNames(t)
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
	reached := map[admodel.ErrorClass]bool{}
	for _, class := range admodel.InternalSentinelClasses {
		reached[class] = true
	}
	for _, class := range admodel.InternalLdapStatusClasses {
		reached[class] = true
	}
	for _, class := range admodel.InternalClassPrecedence {
		if !reached[class] {
			t.Errorf("no sentinel or LDAP status produces %s", class)
		}
	}
}

// Precedence must list each class exactly once. A class missing from it is
// unreachable through Classify however many sentinels map to it, and a
// duplicate makes the order ambiguous to a reader.
func TestPrecedenceCoversEveryClassOnce(t *testing.T) {
	seen := map[admodel.ErrorClass]int{}
	for _, class := range admodel.InternalClassPrecedence {
		seen[class]++
	}
	for class, count := range seen {
		if count != 1 {
			t.Errorf("%s appears %d times in classPrecedence", class, count)
		}
	}
	if seen[admodel.ClassUnclassified] != 0 {
		t.Error("ClassUnclassified must not be in classPrecedence; it is the fallthrough")
	}
	// Every non-zero class value up to the last must be covered, so adding a
	// class without adding it to the precedence list fails here.
	for class := admodel.ClassUncertain; class <= admodel.InternalClassHighest; class++ {
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
		InternalName string
		InternalErr  error
		InternalWant admodel.ErrorClass
		InternalWhy  string
	}{
		{
			"uncertain beats denied",
			errors.Join(admodel.ErrObjectWriteUncertain, admodel.ErrObjectWritePermission), admodel.ClassUncertain, "a write whose outcome is unknown must never be reported as a clean refusal",
		},
		{
			"uncertain beats not-found",
			errors.Join(admodel.ErrObjectWriteUncertain, admodel.ErrDirectoryObjectNotFound), admodel.ClassUncertain, "an absent readback after an accepted write is not a deletion",
		},
		{
			"uncertain beats incomplete",
			errors.Join(admodel.ErrObjectReadback, admodel.ErrIncompleteResult), admodel.ClassUncertain, "the readback being short is why the outcome is unknown",
		},
		{
			"denied beats not-found",
			errors.Join(admodel.ErrObjectWritePermission, admodel.ErrDirectoryObjectNotFound), admodel.ClassDenied, "a search omits objects the identity cannot read, so a denial can present as absence",
		},
		{
			"denied beats conflict",
			errors.Join(admodel.ErrObjectWritePermission, admodel.ErrObjectConcurrency), admodel.ClassDenied, "retrying a refused operation in a loop never succeeds",
		},
		{
			"transport beats incomplete",
			errors.Join(admodel.ErrClosed, admodel.ErrIncompleteResult), admodel.ClassTransport, "a dead session explains the short read",
		},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			if got := admodel.Classify(test.InternalErr); got != test.InternalWant {
				t.Fatalf("Classify = %s, want %s: %s", got, test.InternalWant, test.InternalWhy)
			}
		})
	}
}

func TestClassifyUnrecognisedAndNil(t *testing.T) {
	if got := admodel.Classify(nil); got != admodel.ClassUnclassified {
		t.Errorf("Classify(nil) = %s, want unclassified", got)
	}
	if got := admodel.Classify(
		errors.New("something else entirely"),
	); got != admodel.ClassUnclassified {
		t.Errorf("a foreign error classified as %s; it must not be claimed", got)
	}
	// Unclassified must not satisfy any predicate: a caller that checks each
	// in turn has to fall through to its own handling.
	foreign := fmt.Errorf("wrapped: %w", errors.New("foreign"))
	for name, predicate := range map[string]func(error) bool{
		"IsUncertain": admodel.IsUncertain, "IsDenied": admodel.IsDenied, "IsConflict": admodel.IsConflict,
		"IsAlreadyExists": admodel.IsAlreadyExists, "IsNotFound": admodel.IsNotFound,
		"IsUnsupported": admodel.IsUnsupported, "IsInvalidRequest": admodel.IsInvalidRequest,
		"IsTransport": admodel.IsTransport, "IsIncomplete": admodel.IsIncomplete,
		"IsUnverified": admodel.IsUnverified,
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
		InternalCode uint32
		InternalWant admodel.ErrorClass
	}{
		{50, admodel.ClassDenied},
		{32, admodel.ClassNotFound},
		{68, admodel.ClassAlreadyExists},
		{53, admodel.ClassUnsupported},
		{19, admodel.ClassInvalidRequest},
		// Observed unclassified in the first live mutation run: an undefined
		// attribute, and a value AD DS refuses as already present — which is
		// also how it reports a single-value constraint violation.
		{16, admodel.ClassInvalidRequest},
		{17, admodel.ClassInvalidRequest},
		{20, admodel.ClassInvalidRequest},
		{34, admodel.ClassInvalidRequest},
		{67, admodel.ClassInvalidRequest},
	} {
		err := fmt.Errorf(
			"read failed: %w",
			&admodel.LDAPError{Operation: "Search", Code: test.InternalCode},
		)
		if got := admodel.Classify(err); got != test.InternalWant {
			t.Errorf(
				"LDAP status %d classified as %s, want %s",
				test.InternalCode,
				got,
				test.InternalWant,
			)
		}
	}
	// A status the table does not name contributes nothing rather than a
	// guess, so the joined sentinel decides.
	unknown := errors.Join(
		admodel.ErrIncompleteResult,
		&admodel.LDAPError{Operation: "Search", Code: 4},
	)
	if got := admodel.Classify(unknown); got != admodel.ClassIncomplete {
		t.Errorf("an unnamed status overrode the joined sentinel: got %s", got)
	}
}

// LDAP 20 means a value already exists, not an object. Confusing the two
// would send a caller down the adopt-the-existing-object path for what is
// actually a malformed attribute change.
func TestClassifyKeepsValueExistsApartFromObjectExists(t *testing.T) {
	value := fmt.Errorf("modify: %w", &admodel.LDAPError{Operation: "Modify", Code: 20})
	if got := admodel.Classify(value); got != admodel.ClassInvalidRequest {
		t.Errorf("LDAP 20 classified as %s, want invalid-request", got)
	}
	if admodel.IsAlreadyExists(value) {
		t.Error("a duplicate attribute value reported as an existing object")
	}
	object := fmt.Errorf("add: %w", &admodel.LDAPError{Operation: "Add", Code: 68})
	if !admodel.IsAlreadyExists(object) {
		t.Error("LDAP 68 no longer reports an existing object")
	}
}

// A status and a sentinel disagreeing must resolve through the same
// precedence as two sentinels, not by whichever was inspected first.
func TestClassifyRanksStatusAndSentinelTogether(t *testing.T) {
	err := errors.Join(
		admodel.ErrObjectWriteUncertain,
		&admodel.LDAPError{Operation: "Modify", Code: 50},
	)
	if got := admodel.Classify(err); got != admodel.ClassUncertain {
		t.Fatalf("Classify = %s, want uncertain: status 50 must not demote an uncertain write", got)
	}
}

// Every class must print a distinct name: the strings reach artifacts and
// logs, where two classes sharing one would be indistinguishable.
func TestClassStringsAreDistinct(t *testing.T) {
	seen := map[string]admodel.ErrorClass{}
	for class := admodel.ClassUnclassified; class <= admodel.InternalClassHighest; class++ {
		text := class.String()
		if text == "" {
			t.Errorf("class %d has no name", class)
		}
		if other, ok := seen[text]; ok {
			t.Errorf("classes %d and %d both print %q", other, class, text)
		}
		seen[text] = class
	}
	if admodel.ErrorClass(200).String() != "unclassified" {
		t.Error("an out-of-range class must print as unclassified, not as a valid class")
	}
}

// The wrapper types in this package unwrap to sentinels, so classification has
// to hold through them rather than only on a bare sentinel.
func TestClassifyThroughPackageErrorTypes(t *testing.T) {
	for _, test := range []struct {
		InternalName string
		InternalErr  error
		InternalWant admodel.ErrorClass
	}{
		{
			"DirectoryCapabilityError",
			&admodel.DirectoryCapabilityError{Operation: "read", Required: admodel.DirectoryADDS}, admodel.ClassUnsupported,
		},
		{
			"SearchError",
			&admodel.SearchError{Returned: 3, Cause: admodel.ErrSearchReferences}, admodel.ClassIncomplete,
		},
		{
			"DirectoryReadError",
			&admodel.DirectoryReadError{Operation: "read", Cause: admodel.ErrAttributeUnavailable}, admodel.ClassIncomplete,
		},
		{
			"SearchError wrapping a denial",
			&admodel.SearchError{Returned: 0, Cause: admodel.ErrObjectWritePermission}, admodel.ClassDenied,
		},
	} {
		t.Run(test.InternalName, func(t *testing.T) {
			if got := admodel.Classify(test.InternalErr); got != test.InternalWant {
				t.Fatalf("Classify = %s, want %s", got, test.InternalWant)
			}
		})
	}
}

// LocalServiceAccountNativeError classifies itself through a custom Is method
// rather than by wrapping, which is why Classify tests each sentinel with
// errors.Is instead of walking the error tree once. A tree walk would miss
// this, so it is pinned.
func TestClassifyHonoursCustomIsMethods(t *testing.T) {
	denied := &admodel.LocalServiceAccountNativeError{
		Operation: "NetAddServiceAccount",
		Status:    0xc0000022,
	}
	if got := admodel.Classify(denied); got != admodel.ClassDenied {
		t.Fatalf("Classify = %s, want denied: the custom Is method was not consulted", got)
	}
	other := &admodel.LocalServiceAccountNativeError{
		Operation: "NetAddServiceAccount",
		Status:    0xc0000001,
	}
	if got := admodel.Classify(other); got != admodel.ClassUnclassified {
		t.Fatalf("Classify = %s, want unclassified: an unrelated NTSTATUS must not be claimed", got)
	}
}

// Each predicate must answer for exactly its own class, so a caller can check
// them in any order without two matching the same error.
func TestPredicatesAreMutuallyExclusive(t *testing.T) {
	predicates := map[admodel.ErrorClass]func(error) bool{
		admodel.ClassUncertain:      admodel.IsUncertain,
		admodel.ClassDenied:         admodel.IsDenied,
		admodel.ClassConflict:       admodel.IsConflict,
		admodel.ClassAlreadyExists:  admodel.IsAlreadyExists,
		admodel.ClassNotFound:       admodel.IsNotFound,
		admodel.ClassUnsupported:    admodel.IsUnsupported,
		admodel.ClassInvalidRequest: admodel.IsInvalidRequest,
		admodel.ClassTransport:      admodel.IsTransport,
		admodel.ClassIncomplete:     admodel.IsIncomplete,
		admodel.ClassUnverified:     admodel.IsUnverified,
	}
	for _, class := range admodel.InternalClassPrecedence {
		if _, ok := predicates[class]; !ok {
			t.Fatalf("%s has no exported predicate", class)
		}
	}
	samples := map[admodel.ErrorClass]error{
		admodel.ClassUncertain:      admodel.ErrObjectWriteUncertain,
		admodel.ClassDenied:         admodel.ErrObjectWritePermission,
		admodel.ClassConflict:       admodel.ErrObjectConcurrency,
		admodel.ClassAlreadyExists:  admodel.ErrObjectAlreadyExists,
		admodel.ClassNotFound:       admodel.ErrDirectoryObjectNotFound,
		admodel.ClassUnsupported:    admodel.ErrUnsupported,
		admodel.ClassInvalidRequest: admodel.ErrInvalidIdentity,
		admodel.ClassTransport:      admodel.ErrClosed,
		admodel.ClassIncomplete:     admodel.ErrIncompleteResult,
		admodel.ClassUnverified:     admodel.ErrObjectUnverifiable,
	}
	for class, sample := range samples {
		for other, predicate := range predicates {
			if got := predicate(sample); got != (class == other) {
				t.Errorf("%s predicate returned %v for a %s error", other, got, class)
			}
		}
	}
}
