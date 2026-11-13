package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Optional so existing read-only/session implementations need not add a new
// primitive. The Windows implementation copies owned data without treating
// a range marker as completion or suppressing native/cleanup errors.
type rangedBaseObjectSession interface {
	rangedBaseObject(context.Context, string, []string) (map[string][][]byte, error)
}

const optionalFeatureMaxScopeValues = 1 << 20
const optionalFeatureMaxScopeReads = 4096

func readOptionalFeatureScopes(ctx context.Context, session directorySession, feature *OptionalFeature) error {
	feature.EnabledScopes = nil
	feature.EnabledScopesState = AttributePartial
	feature.EnabledScopeObjects = nil
	if feature.DistinguishedName == "" {
		return ErrInvalidResult
	}
	read := session.baseObject
	if ranged, ok := session.(rangedBaseObjectSession); ok {
		read = ranged.rangedBaseObject
	}
	var start uint64
	seen := map[string]bool{}
	for len(feature.EnabledScopeObjects) < optionalFeatureMaxScopeReads {
		if err := context.Cause(ctx); err != nil {
			return errors.Join(ErrIncompleteResult, err)
		}
		requested := "msDS-EnabledFeatureBL"
		if start != 0 {
			requested = fmt.Sprintf("%s;range=%d-*", requested, start)
		}
		properties := []string{requested, "distinguishedName", "objectGUID"}
		attrs, readErr := read(ctx, feature.DistinguishedName, properties)
		feature.EnabledScopeObjects = append(feature.EnabledScopeObjects, Object{DistinguishedName: feature.DistinguishedName, Attributes: attrs, RequestedProperties: properties})
		values, next, terminal, present, rangeErr := optionalFeatureScopeRange(attrs, start)
		// Identity is needed across a range sequence: do not stitch values from
		// a replacement object that happened to acquire the same DN.
		if !terminal || start != 0 || hasOptionalFeatureRange(attrs) {
			rangeErr = errors.Join(rangeErr, optionalFeatureRangeIdentity(attrs, *feature))
		}
		if rangeErr == nil && len(feature.EnabledScopes)+len(values) > optionalFeatureMaxScopeValues {
			rangeErr = fmt.Errorf("%w: enabled-scope value bound exceeded", ErrIncompleteResult)
		}
		if rangeErr == nil {
			decoded, valueErr := optionalFeatureScopeTexts(values, seen)
			rangeErr = valueErr
			if valueErr == nil {
				feature.EnabledScopes = append(feature.EnabledScopes, decoded...)
			}
		}
		if err := errors.Join(readErr, rangeErr, context.Cause(ctx)); err != nil {
			return errors.Join(ErrIncompleteResult, err)
		}
		if terminal {
			feature.EnabledScopesState = AttributeAbsent
			if present {
				feature.EnabledScopesState = AttributePresent
			}
			return nil
		}
		start = next
	}
	return fmt.Errorf("%w: enabled-scope read bound exceeded", ErrIncompleteResult)
}

func hasOptionalFeatureRange(attrs map[string][][]byte) bool {
	for name := range attrs {
		if strings.HasPrefix(strings.ToLower(name), "msds-enabledfeaturebl;range=") {
			return true
		}
	}
	return false
}

func optionalFeatureRangeIdentity(attrs map[string][][]byte, feature OptionalFeature) error {
	d := rootDSEDecoder{attributes: attrs}
	dn := d.text("distinguishedName")
	guid := copiedBinary(&d, "objectGUID", 16)
	if dn == nil || !strings.EqualFold(*dn, feature.DistinguishedName) || guid == nil || feature.ObjectGUID == nil || !strings.EqualFold(optionalFeatureGUIDString(guid), *feature.ObjectGUID) {
		return errors.Join(ErrIncompleteResult, errors.Join(d.errors...))
	}
	return errors.Join(d.errors...)
}

// The empty bare attribute accompanying a first range is required by MS-ADTS
// for an un-ranged request that exceeds MaxValRange. Nonempty bare values plus
// a range, multiple range descriptions, resets and gaps are inconsistent.
func optionalFeatureScopeRange(attrs map[string][][]byte, start uint64) (values [][]byte, next uint64, terminal, present bool, err error) {
	const attribute = "msds-enabledfeaturebl"
	var ranged string
	bare := false
	for name, rows := range attrs {
		key := strings.ToLower(name)
		if key == attribute {
			if bare {
				return nil, 0, false, false, ErrInvalidResult
			}
			bare = true
			values = rows
		}
		if strings.HasPrefix(key, attribute+";range=") {
			if ranged != "" {
				return nil, 0, false, false, ErrInvalidResult
			}
			ranged = name
		}
	}
	if ranged == "" {
		if start != 0 {
			return nil, 0, false, false, ErrIncompleteResult
		}
		return values, 0, true, bare, nil
	}
	if len(values) > 0 {
		return nil, 0, false, false, ErrInvalidResult
	}
	values = attrs[ranged]
	low, high, ok := strings.Cut(strings.TrimPrefix(strings.ToLower(ranged), attribute+";range="), "-")
	first, parseErr := optionalFeatureRangeIndex(low)
	if !ok || parseErr != nil || first != start {
		return nil, 0, false, false, ErrIncompleteResult
	}
	if high == "*" {
		if len(values) == 0 {
			return nil, 0, false, false, ErrIncompleteResult
		}
		return values, 0, true, true, nil
	}
	last, parseErr := optionalFeatureRangeIndex(high)
	if parseErr != nil || last < first || last-first+1 != uint64(len(values)) || last == 1<<32-1 {
		return nil, 0, false, false, ErrIncompleteResult
	}
	return values, last + 1, false, true, nil
}

func optionalFeatureRangeIndex(value string) (uint64, error) {
	if value == "" {
		return 0, ErrInvalidResult
	}
	for _, b := range []byte(value) {
		if b < '0' || b > '9' {
			return 0, ErrInvalidResult
		}
	}
	index, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, ErrInvalidResult
	}
	return index, nil
}

func optionalFeatureScopeTexts(values [][]byte, seen map[string]bool) ([]string, error) {
	texts := make([]string, 0, len(values))
	within := map[string]bool{}
	for _, value := range values {
		if len(value) == 0 || !utf8.Valid(value) || strings.ContainsRune(string(value), 0) {
			return nil, ErrInvalidResult
		}
		text := string(value)
		key := strings.ToLower(text)
		if seen[key] || within[key] {
			return nil, fmt.Errorf("%w: duplicate enabled-scope value", ErrIncompleteResult)
		}
		within[key] = true
		texts = append(texts, text)
	}
	for key := range within {
		seen[key] = true
	}
	return texts, nil
}
