package model

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
)

// InternalVerifyObjectWriteWithSchema distinguishes an observed DS-DN text
// normalization from a contradicted effect. It never rewrites the request or
// returned bytes, and equivalent text is still unverified rather than exact.
func InternalVerifyObjectWriteWithSchema(ctx context.Context, session InternalDirectorySession, root RootDSE,
	result *ObjectMutationResult, modifications []InternalLdapAttributeModification, name string,
) error {
	observation := *result
	observation.Verified = false
	original := InternalVerifyObjectWrite(&observation, modifications, name)
	result.Verified = false
	if result.After == nil || !result.ReadbackComplete {
		return original
	}
	remains, err := internalObjectDNRemovalRemains(ctx, session, root, result.After, modifications)
	if err != nil || remains {
		return errors.Join(ErrObjectVerification, original, err)
	}
	if !errors.Is(original, ErrObjectVerification) {
		result.Verified = observation.Verified
		return original
	}
	adjusted := slices.Clone(modifications)
	normalized := false
	for i, modification := range modifications {
		if modification.InternalOperation == 1 {
			continue
		}
		returned, state := result.After.Attribute(modification.InternalAttribute)
		if state != AttributePresent {
			continue
		}
		values := slices.Clone(modification.InternalValues)
		checked, dnSyntax := false, false
		for at, requested := range values {
			if slices.ContainsFunc(returned, func(value []byte) bool { return bytes.Equal(value, requested) }) {
				continue
			}
			for _, value := range returned {
				if !internalSameDNRepresentation(string(requested), string(value)) {
					continue
				}
				if !checked {
					var err error
					dnSyntax, err = internalObjectAttributeDNSyntax(ctx, session, root, modification.InternalAttribute)
					if err != nil {
						return errors.Join(original, err)
					}
					checked = true
				}
				if dnSyntax {
					values[at], normalized = value, true
				}
				break
			}
		}
		adjusted[i].InternalValues = values
	}
	if normalized {
		observation := *result
		if err := InternalVerifyObjectWrite(&observation, adjusted, name); err == nil || errors.Is(err, ErrObjectUnverifiable) {
			return ErrObjectUnverifiable
		}
	}
	return original
}

// A byte-different representation of a removed DS-DN value still contradicts
// the requested effect. Do not let the strict byte comparator prove its absence.
func internalObjectDNRemovalRemains(ctx context.Context, session InternalDirectorySession, root RootDSE,
	object *Object, modifications []InternalLdapAttributeModification,
) (bool, error) {
	for _, modification := range modifications {
		if modification.InternalOperation != 1 || len(modification.InternalValues) == 0 {
			continue
		}
		returned, state := object.Attribute(modification.InternalAttribute)
		if state != AttributePresent {
			continue
		}
		for _, requested := range modification.InternalValues {
			for _, value := range returned {
				if bytes.Equal(value, requested) || !internalSameDNRepresentation(string(requested), string(value)) {
					continue
				}
				dnSyntax, err := internalObjectAttributeDNSyntax(ctx, session, root, modification.InternalAttribute)
				if err != nil || dnSyntax {
					return dnSyntax, err
				}
			}
		}
	}
	return false, nil
}

func internalObjectAttributeDNSyntax(ctx context.Context, session InternalDirectorySession, root RootDSE, attribute string) (bool, error) {
	if root.SchemaNamingContext == nil || *root.SchemaNamingContext == "" {
		return false, ErrIncompleteResult
	}
	search, err := InternalSearchIdentitySession(ctx, session, SearchOptions{
		Base: *root.SchemaNamingContext, Scope: ScopeOneLevel,
		Filter:     "(&(objectClass=attributeSchema)(lDAPDisplayName=" + InternalLdapLiteral(attribute) + "))",
		Properties: []string{"lDAPDisplayName", "attributeSyntax", "oMSyntax", "oMObjectClass"}, PageSize: 2, ResultLimit: 2,
	})
	if err != nil {
		return false, err
	}
	if !search.Complete || len(search.Objects) != 1 {
		return false, ErrIncompleteResult
	}
	object := search.Objects[0]
	decoder := InternalRootDSEDecoder{InternalAttributes: object.Attributes}
	name, syntax := decoder.InternalText("lDAPDisplayName"), decoder.InternalText("attributeSyntax")
	omSyntax := InternalDecodeScalar(&decoder, "oMSyntax", InternalParseUint32)
	if len(decoder.InternalErrors) != 0 || name == nil || syntax == nil || omSyntax == nil || !strings.EqualFold(*name, attribute) {
		return false, errors.Join(ErrAttributeUnavailable, errors.Join(decoder.InternalErrors...))
	}
	if *syntax != "2.5.5.1" || *omSyntax != 127 {
		return false, nil
	}
	value, err := object.Values("oMObjectClass").Single()
	if err != nil {
		return false, err
	}
	// MS-ADTS 3.1.1.2.2.2 identifies Object(DS-DN) by this exact triple.
	return bytes.Equal(value.Bytes(), []byte{0x2b, 0x0c, 2, 0x87, 0x73, 0x1c, 0, 0x85, 0x4a}), nil
}

// Attribute types and decoded escapes/AVA ordering can differ representationally.
// Value case differences require the AVA attribute's equality matching rule;
// the existing scope comparator's Unicode folding cannot prove that here.
func internalSameDNRepresentation(left, right string) bool {
	a, firstErr := InternalParseIdentityDN(left)
	b, secondErr := InternalParseIdentityDN(right)
	if firstErr != nil || secondErr != nil || len(a) != len(b) {
		return false
	}
	for at, rdn := range a {
		if len(rdn) != len(b[at]) {
			return false
		}
		used := make([]bool, len(b[at]))
		for _, ava := range rdn {
			found := false
			for i, other := range b[at] {
				if !used[i] && ava == other {
					used[i], found = true, true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}
