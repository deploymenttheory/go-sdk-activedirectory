package model

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
	InternalObjectAssertionControl  = "1.3.6.1.1.12"
	InternalObjectTreeDeleteControl = "1.2.840.113556.1.4.805"
)

func InternalObjectAttributeName(name string) bool {
	return InternalAttributeDescription.MatchString(name) && !strings.Contains(name, ";") &&
		len(name) > 0 &&
		((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z'))
}

func InternalValidateObjectOptions(identity Identity, options ObjectMutationOptions) error {
	if err := InternalValidateIdentityOperation(
		identity,
		ResolveIdentityOptions{Partition: options.Partition, Properties: options.Properties},
	); err != nil {
		return err
	}
	for _, property := range options.Properties {
		if property == "1.1" {
			return ErrInvalidProperty
		}
	}
	return nil
}

func InternalValidateObjectAttribute(name string) error {
	if !InternalObjectAttributeName(name) {
		return ErrInvalidObjectMutation
	}
	switch strings.ToLower(name) {
	case "objectguid", "distinguishedname", "objectclass", "name":
		return fmt.Errorf(
			"%w: use the operation's identity, Class or Name field",
			ErrInvalidObjectMutation,
		)
	}
	return nil
}

func InternalObjectRawValues(raw []RawValue) ([][]byte, error) {
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

func InternalCreateObjectAttributes(
	attributes map[string][]RawValue,
) ([]InternalLdapAttributeModification, error) {
	names := make([]string, 0, len(attributes))
	for name := range attributes {
		names = append(names, name)
	}
	sort.Strings(names)
	mods := make([]InternalLdapAttributeModification, 0, len(attributes))
	seen := make(map[string]bool, len(attributes))
	for _, name := range names {
		if err := InternalValidateObjectAttribute(name); err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		if seen[key] {
			return nil, fmt.Errorf("%w: repeated attribute", ErrInvalidObjectMutation)
		}
		seen[key] = true
		values, err := InternalObjectRawValues(attributes[name])
		if err != nil {
			return nil, err
		}
		mods = append(
			mods,
			InternalLdapAttributeModification{
				InternalOperation: 0,
				InternalAttribute: name,
				InternalValues:    values,
			},
		)
	}
	return mods, nil
}

func InternalObjectChanges(changes []AttributeChange) ([]InternalLdapAttributeModification, error) {
	if len(changes) == 0 {
		return nil, ErrInvalidObjectMutation
	}
	mods := make([]InternalLdapAttributeModification, 0, len(changes))
	seen := make(map[string][]int, len(changes))
	for _, change := range changes {
		if err := InternalValidateObjectAttribute(change.Attribute); err != nil {
			return nil, err
		}
		key := strings.ToLower(change.Attribute)
		mod := InternalLdapAttributeModification{InternalAttribute: change.Attribute}
		if change.Kind == AttributeClear {
			if len(change.Values) != 0 {
				return nil, ErrInvalidObjectMutation
			}
			mod.InternalOperation = 1
		} else {
			switch change.Kind {
			case AttributeSet:
				mod.InternalOperation = 2
			case AttributeAddValues:
				mod.InternalOperation = 0
			case AttributeRemoveValues:
				mod.InternalOperation = 1
			default:
				return nil, ErrInvalidObjectMutation
			}
			var err error
			mod.InternalValues, err = InternalObjectRawValues(change.Values)
			if err != nil {
				return nil, err
			}
		}
		if previous := seen[key]; len(previous) != 0 {
			first := mods[previous[0]]
			if len(previous) != 1 || len(first.InternalValues) == 0 ||
				len(mod.InternalValues) == 0 ||
				!((first.InternalOperation == 0 && mod.InternalOperation == 1) || (first.InternalOperation == 1 && mod.InternalOperation == 0)) {
				return nil, fmt.Errorf(
					"%w: conflicting changes for one attribute",
					ErrInvalidObjectMutation,
				)
			}
			for _, oldValue := range first.InternalValues {
				for _, newValue := range mod.InternalValues {
					if string(oldValue) == string(newValue) {
						return nil, fmt.Errorf(
							"%w: overlapping add/remove values",
							ErrInvalidObjectMutation,
						)
					}
				}
			}
			// Removing before adding allows strict replacement of a single
			// value without an intermediate constraint violation. Both remain
			// in this one atomic Modify request, with no permissive control.
			if first.InternalOperation == 0 {
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
func InternalEscapeObjectName(value string) string {
	var escaped strings.Builder
	for i := 0; i < len(value); i++ {
		b := value[i]
		if strings.ContainsRune(`",+;<>\=`, rune(b)) || (b == '#' && i == 0) ||
			(b == ' ' && (i == 0 || i == len(value)-1)) {
			escaped.WriteByte('\\')
		}
		escaped.WriteByte(b)
	}
	return escaped.String()
}

func InternalObjectClassNamingAttribute(
	ctx context.Context,
	session InternalDirectorySession,
	root RootDSE,
	class string,
) (string, error) {
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
		result, err := InternalSearchIdentitySession(
			ctx,
			session,
			SearchOptions{
				Base:  *root.SchemaNamingContext,
				Scope: ScopeOneLevel,
				Filter: "(&(objectClass=classSchema)(lDAPDisplayName=" + InternalLdapLiteral(
					class,
				) + "))",
				Properties:  []string{"rDNAttID", "subClassOf", "objectClassCategory", "isDefunct"},
				PageSize:    2,
				ResultLimit: 2,
			},
		)
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
		decoder := InternalRootDSEDecoder{InternalAttributes: result.Objects[0].Attributes}
		naming, parent := decoder.InternalText("rDNAttID"), decoder.InternalText("subClassOf")
		category := InternalDecodeScalar(&decoder, "objectClassCategory", InternalParseUint32)
		defunct := InternalDecodeScalar(&decoder, "isDefunct", InternalParseLDAPBool)
		if len(decoder.InternalErrors) != 0 {
			return "", errors.Join(decoder.InternalErrors...)
		}
		if depth == 0 &&
			(category == nil || (*category != 0 && *category != 1) || (defunct != nil && *defunct)) {
			return "", fmt.Errorf(
				"%w: Class must be an active structural schema class",
				ErrInvalidObjectMutation,
			)
		}
		if naming != nil {
			if !InternalObjectAttributeName(*naming) {
				return "", ErrInvalidResult
			}
			return *naming, nil
		}
		if parent == nil || !InternalObjectAttributeName(*parent) {
			return "", ErrIncompleteResult
		}
		class = *parent
	}
	return "", ErrIncompleteResult
}

func InternalObjectWriteControls(
	root RootDSE,
	source Endpoint,
	options ObjectMutationOptions,
	guid GUID,
	recursive bool,
) ([]InternalLdapWriteControl, error) {
	var controls []InternalLdapWriteControl
	if expected := options.ExpectedVersion; expected != nil {
		if expected.Source.Port != source.Port ||
			!strings.EqualFold(expected.Source.Host, source.Host) ||
			expected.GUID != guid {
			return nil, ErrObjectConcurrency
		}
		if !slices.Contains(root.SupportedControls, InternalObjectAssertionControl) {
			return nil, ErrObjectControlUnsupported
		}
		// A tree deletion has per-descendant effects; a root version cannot
		// guard the entire subtree or promise an atomic conditional delete.
		if recursive {
			return nil, ErrObjectControlUnsupported
		}
		controls = append(
			controls,
			InternalLdapWriteControl{
				InternalOid:      InternalObjectAssertionControl,
				InternalCritical: true,
				InternalValue:    InternalObjectVersionAssertion(*expected),
			},
		)
	}
	if recursive {
		if !slices.Contains(root.SupportedControls, InternalObjectTreeDeleteControl) {
			return nil, ErrObjectControlUnsupported
		}
		controls = append(
			controls,
			InternalLdapWriteControl{
				InternalOid:      InternalObjectTreeDeleteControl,
				InternalCritical: true,
			},
		)
	}
	return controls, nil
}

// Fixed RFC4511 Filter encoding: AND of two equalityMatch filters. Every TLV
// is shorter than 128 octets, including the largest uint64 decimal value.
func InternalObjectVersionAssertion(version ObjectVersion) []byte {
	equality := func(attribute string, value []byte) []byte {
		body := append([]byte{4, byte(len(attribute))}, attribute...)
		body = append(body, 4, byte(len(value)))
		body = append(body, value...)
		return append([]byte{0xa3, byte(len(body))}, body...)
	}
	body := equality("objectGUID", version.GUID.Bytes())
	body = append(
		body,
		equality("uSNChanged", []byte(strconv.FormatUint(version.USNChanged, 10)))...)
	return append([]byte{0xa0, byte(len(body))}, body...)
}

func InternalVerifyObjectWrite(
	result *ObjectMutationResult,
	modifications []InternalLdapAttributeModification,
	name string,
) error {
	if result.After == nil || !result.ReadbackComplete {
		return ErrObjectVerification
	}
	if name != "" {
		dn, err := InternalParseIdentityDN(result.After.DistinguishedName)
		if err != nil || len(dn[0]) != 1 || dn[0][0].InternalBinary ||
			dn[0][0].InternalValue != name {
			return ErrObjectVerification
		}
	}
	// An outcome no readback could ever settle is reported separately from one
	// the readback contradicted. Both leave Verified false, but only the second
	// means the directory may not hold what was asked for.
	unverifiable := false
	for _, mod := range modifications {
		values, state := result.After.Attribute(mod.InternalAttribute)
		clearing := mod.InternalOperation == 1 && len(mod.InternalValues) == 0
		if state != AttributePresent {
			// Omission can mean denied visibility rather than absence, and
			// ranged responses are incomplete. For a Clear or a Remove,
			// absence is also exactly what success looks like, so nothing is
			// contradicted and nothing can be proved. For a change that should
			// have put a value there, absence is a real disagreement.
			if mod.InternalOperation == 1 {
				unverifiable = true
				continue
			}
			return ErrObjectVerification
		}
		if clearing {
			// Asked for empty and the attribute came back present: that is a
			// contradiction, not a missing proof.
			return ErrObjectVerification
		}
		returned := make(map[string]bool, len(values))
		for _, value := range values {
			returned[string(value)] = true
		}
		if mod.InternalOperation == 2 && len(returned) != len(mod.InternalValues) {
			return ErrObjectVerification
		}
		for _, value := range mod.InternalValues {
			present := returned[string(value)]
			if (mod.InternalOperation == 1 && present) || (mod.InternalOperation != 1 && !present) {
				return ErrObjectVerification
			}
		}
	}
	if unverifiable {
		return ErrObjectUnverifiable
	}
	result.Verified = true
	return nil
}
