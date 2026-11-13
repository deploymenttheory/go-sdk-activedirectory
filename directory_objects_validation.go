package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	objectAssertionControl  = "1.3.6.1.1.12"
	objectTreeDeleteControl = "1.2.840.113556.1.4.805"
)

func objectAttributeName(name string) bool {
	return attributeDescription.MatchString(name) && !strings.Contains(name, ";") && len(name) > 0 && ((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z'))
}

func validateObjectOptions(identity Identity, options ObjectMutationOptions) error {
	if err := validateIdentityOperation(identity, ResolveIdentityOptions{Partition: options.Partition, Properties: options.Properties}); err != nil {
		return err
	}
	for _, property := range options.Properties {
		if property == "1.1" {
			return ErrInvalidProperty
		}
	}
	return nil
}

func validateObjectAttribute(name string) error {
	if !objectAttributeName(name) {
		return ErrInvalidObjectMutation
	}
	switch strings.ToLower(name) {
	case "objectguid", "distinguishedname", "objectclass", "name":
		return fmt.Errorf("%w: use the operation's identity, Class or Name field", ErrInvalidObjectMutation)
	}
	return nil
}

func objectRawValues(raw []RawValue) ([][]byte, error) {
	if len(raw) == 0 {
		return nil, ErrInvalidObjectMutation
	}
	values := make([][]byte, len(raw))
	seen := make(map[string]bool, len(raw))
	for i, value := range raw {
		values[i] = value.Bytes()
		key := string(values[i])
		if seen[key] {
			return nil, fmt.Errorf("%w: duplicate raw value", ErrInvalidObjectMutation)
		}
		seen[key] = true
	}
	return values, nil
}

func createObjectAttributes(attributes map[string][]RawValue) ([]ldapAttributeModification, error) {
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	mods := make([]ldapAttributeModification, 0, len(attributes))
	seen := make(map[string]bool, len(attributes))
	for _, name := range names {
		if err := validateObjectAttribute(name); err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		if seen[key] {
			return nil, fmt.Errorf("%w: repeated attribute", ErrInvalidObjectMutation)
		}
		seen[key] = true
		values, err := objectRawValues(attributes[name])
		if err != nil {
			return nil, err
		}
		mods = append(mods, ldapAttributeModification{operation: 0, attribute: name, values: values})
	}
	return mods, nil
}

func objectChanges(changes []AttributeChange) ([]ldapAttributeModification, error) {
	if len(changes) == 0 {
		return nil, ErrInvalidObjectMutation
	}
	mods := make([]ldapAttributeModification, 0, len(changes))
	seen := make(map[string][]int, len(changes))
	for _, change := range changes {
		if err := validateObjectAttribute(change.Attribute); err != nil {
			return nil, err
		}
		key := strings.ToLower(change.Attribute)
		mod := ldapAttributeModification{attribute: change.Attribute}
		if change.Kind == AttributeClear {
			if len(change.Values) != 0 {
				return nil, ErrInvalidObjectMutation
			}
			mod.operation = 1
		} else {
			switch change.Kind {
			case AttributeSet:
				mod.operation = 2
			case AttributeAddValues:
				mod.operation = 0
			case AttributeRemoveValues:
				mod.operation = 1
			default:
				return nil, ErrInvalidObjectMutation
			}
			var err error
			mod.values, err = objectRawValues(change.Values)
			if err != nil {
				return nil, err
			}
		}
		if previous := seen[key]; len(previous) != 0 {
			first := mods[previous[0]]
			if len(previous) != 1 || len(first.values) == 0 || len(mod.values) == 0 || !((first.operation == 0 && mod.operation == 1) || (first.operation == 1 && mod.operation == 0)) {
				return nil, fmt.Errorf("%w: conflicting changes for one attribute", ErrInvalidObjectMutation)
			}
			for _, oldValue := range first.values {
				for _, newValue := range mod.values {
					if string(oldValue) == string(newValue) {
						return nil, fmt.Errorf("%w: overlapping add/remove values", ErrInvalidObjectMutation)
					}
				}
			}
			// Removing before adding allows strict replacement of a single
			// value without an intermediate constraint violation. Both remain
			// in this one atomic Modify request, with no permissive control.
			if first.operation == 0 {
				mods[previous[0]], mod = mod, first
			}
		}
		seen[key] = append(seen[key], len(mods))
		mods = append(mods, mod)
	}
	return mods, nil
}

// RFC4514 escaping applies to the value alone, preserving literal UTF-8 and
// preventing a user-supplied comma/plus from introducing another DN component.
func escapeObjectName(value string) string {
	var escaped strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if strings.ContainsRune(`",+;<>\=`, rune(b)) || (b == '#' && i == 0) || (b == ' ' && (i == 0 || i == len(value)-1)) {
			escaped.WriteByte('\\')
		}
		escaped.WriteByte(b)
	}
	return escaped.String()
}

func objectClassNamingAttribute(ctx context.Context, session directorySession, root RootDSE, class string) (string, error) {
	if root.SchemaNamingContext == nil || *root.SchemaNamingContext == "" {
		return "", ErrIncompleteResult
	}
	seen := map[string]bool{}
	for depth := 0; depth < 128; depth++ {
		key := strings.ToLower(class)
		if seen[key] {
			return "", ErrInvalidResult
		}
		seen[key] = true
		result, err := searchIdentitySession(ctx, session, SearchOptions{Base: *root.SchemaNamingContext, Scope: ScopeOneLevel, Filter: "(&(objectClass=classSchema)(lDAPDisplayName=" + ldapLiteral(class) + "))", Properties: []string{"rDNAttID", "subClassOf", "objectClassCategory", "isDefunct"}, PageSize: 2, ResultLimit: 2})
		if err != nil {
			return "", err
		}
		if len(result.Objects) > 1 {
			return "", ErrAmbiguousIdentity
		}
		if !result.Complete {
			return "", ErrIncompleteResult
		}
		if len(result.Objects) == 0 {
			return "", ErrDirectoryObjectNotFound
		}
		decoder := rootDSEDecoder{attributes: result.Objects[0].Attributes}
		naming, parent := decoder.text("rDNAttID"), decoder.text("subClassOf")
		category := decodeScalar(&decoder, "objectClassCategory", parseUint32)
		defunct := decodeScalar(&decoder, "isDefunct", parseLDAPBool)
		if len(decoder.errors) != 0 {
			return "", errors.Join(decoder.errors...)
		}
		if depth == 0 && (category == nil || (*category != 0 && *category != 1) || (defunct != nil && *defunct)) {
			return "", fmt.Errorf("%w: Class must be an active structural schema class", ErrInvalidObjectMutation)
		}
		if naming != nil {
			if !objectAttributeName(*naming) {
				return "", ErrInvalidResult
			}
			return *naming, nil
		}
		if parent == nil || !objectAttributeName(*parent) {
			return "", ErrIncompleteResult
		}
		class = *parent
	}
	return "", ErrIncompleteResult
}

func objectWriteControls(root RootDSE, source Endpoint, options ObjectMutationOptions, guid GUID, recursive bool) ([]ldapWriteControl, error) {
	var controls []ldapWriteControl
	if expected := options.ExpectedVersion; expected != nil {
		if expected.Source.Port != source.Port || !strings.EqualFold(expected.Source.Host, source.Host) || expected.GUID != guid {
			return nil, ErrObjectConcurrency
		}
		if !slices.Contains(root.SupportedControls, objectAssertionControl) {
			return nil, ErrObjectControlUnsupported
		}
		// A tree deletion has per-descendant effects; a root version cannot
		// guard the entire subtree or promise an atomic conditional delete.
		if recursive {
			return nil, ErrObjectControlUnsupported
		}
		controls = append(controls, ldapWriteControl{oid: objectAssertionControl, critical: true, value: objectVersionAssertion(*expected)})
	}
	if recursive {
		if !slices.Contains(root.SupportedControls, objectTreeDeleteControl) {
			return nil, ErrObjectControlUnsupported
		}
		controls = append(controls, ldapWriteControl{oid: objectTreeDeleteControl, critical: true})
	}
	return controls, nil
}

// Fixed RFC4511 Filter encoding: AND of two equalityMatch filters. Every TLV
// is shorter than 128 octets, including the largest uint64 decimal value.
func objectVersionAssertion(version ObjectVersion) []byte {
	equality := func(attribute string, value []byte) []byte {
		body := append([]byte{4, byte(len(attribute))}, attribute...)
		body = append(body, 4, byte(len(value)))
		body = append(body, value...)
		return append([]byte{0xa3, byte(len(body))}, body...)
	}
	body := equality("objectGUID", version.GUID.Bytes())
	body = append(body, equality("uSNChanged", []byte(strconv.FormatUint(version.USNChanged, 10)))...)
	return append([]byte{0xa0, byte(len(body))}, body...)
}

func verifyObjectWrite(result *ObjectMutationResult, modifications []ldapAttributeModification, name string) error {
	if result.After == nil || !result.ReadbackComplete {
		return ErrObjectVerification
	}
	if name != "" {
		dn, err := parseIdentityDN(result.After.DistinguishedName)
		if err != nil || len(dn[0]) != 1 || dn[0][0].binary || dn[0][0].value != name {
			return ErrObjectVerification
		}
	}
	for _, mod := range modifications {
		values, state := result.After.Attribute(mod.attribute)
		// Omission can mean denied visibility. Ranged responses are incomplete.
		// An absent whole attribute cannot prove a Clear or Remove succeeded.
		if state != AttributePresent || (mod.operation == 1 && len(mod.values) == 0) {
			return ErrObjectVerification
		}
		returned := make(map[string]bool, len(values))
		for _, value := range values {
			returned[string(value)] = true
		}
		if mod.operation == 2 && len(returned) != len(mod.values) {
			return ErrObjectVerification
		}
		for _, value := range mod.values {
			present := returned[string(value)]
			if (mod.operation == 1 && present) || (mod.operation != 1 && !present) {
				return ErrObjectVerification
			}
		}
	}
	result.Verified = true
	return nil
}
