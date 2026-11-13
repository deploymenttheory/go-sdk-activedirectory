package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// GroupMemberLinksOptions bounds one read on one authenticated connection. Zero
// limits select defaults: 100,000 values, 1,000 ranges and 64 MiB of attribute
// bytes. A received batch is retained even if it crosses a limit; no next batch
// is requested. Limits bound accumulated work, not the native in-flight reply.
type GroupMemberLinksOptions struct {
	Partition                      string
	IncludeTTL                     bool
	MaxValues, MaxRanges, MaxBytes int
}

// GroupMemberLink is a direct member attribute value, not a resolved principal
// or recursive membership. RemainingTTLSeconds is populated only for returned
// TTL-DNs; nil means no TTL was returned, not necessarily a permanent link when
// IncludeTTL was false. ObservedAt is a client timestamp, not a server expiry.
type GroupMemberLink struct {
	DistinguishedName   string
	RemainingTTLSeconds *uint64
	Raw                 string
	ObservedAt          time.Time
}

type GroupMemberRange struct {
	RequestedProperty string
	Attributes        map[string][][]byte
	ObservedAt        time.Time
	Error             error // Native read/cleanup error; validation errors are returned by the operation.
}

// Complete means all returned ranges were contiguous, bounded and decoded with
// the same objectGUID/uSNChanged. It does not establish ACL visibility or a
// transactional snapshot: expiring links can vanish without a USN change.
// AttributeReturned distinguishes an omitted member attribute from an explicit
// empty response. Neither omission nor Complete proves an empty group.
type GroupMemberLinksResult struct {
	Observation       IdentityResult
	Members           []GroupMemberLink
	Ranges            []GroupMemberRange
	AttributeReturned bool
	Complete          bool
	Version           *ObjectVersion
}

type groupMemberReader interface {
	groupMemberBaseObject(context.Context, string, []string, bool) (map[string][][]byte, error)
}

func normalizeGroupMemberLinks(options GroupMemberLinksOptions) (GroupMemberLinksOptions, error) {
	if options.MaxValues < 0 || options.MaxRanges < 0 || options.MaxBytes < 0 {
		return options, ErrInvalidGroupMembership
	}
	if options.MaxValues == 0 {
		options.MaxValues = 100000
	}
	if options.MaxRanges == 0 {
		options.MaxRanges = 1000
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = 64 << 20
	}
	return options, nil
}

// GroupMemberLinks follows every member range, retaining each raw response on
// failure. Primary-group membership, nested expansion, FSP resolution, referral
// chasing and principal-to-group discovery are deliberately separate operations.
func (c *Client) GroupMemberLinks(ctx context.Context, identity Identity, options GroupMemberLinksOptions) (result GroupMemberLinksResult, err error) {
	options, err = normalizeGroupMemberLinks(options)
	if err != nil {
		return result, err
	}
	resolve := groupIdentityOptions(identity, options.Partition, []string{"uSNChanged"})
	if err = validateIdentityOperation(identity, resolve); err != nil {
		return result, err
	}
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, readErr := readIdentityRoot(ctx, c.session)
		if readErr != nil {
			return readErr
		}
		if root.Capabilities().Type == DirectoryADDS && (c.config.Endpoint.Port == 3268 || c.config.Endpoint.Port == 3269) {
			return ErrGroupMembershipTarget
		}
		if options.IncludeTTL && !slices.Contains(root.SupportedControls, groupLinkTTL) {
			return ErrGroupMembershipTTLUnsupported
		}
		result.Observation, readErr = resolveIdentitySession(ctx, c.session, c.config, root, identity, resolve)
		if readErr != nil {
			return readErr
		}
		if err := groupClass(*result.Observation.Object); err != nil {
			return err
		}
		guid, usn, err := groupMemberVersion(*result.Observation.Object)
		if err != nil {
			return err
		}
		result.Version = &ObjectVersion{Source: c.config.Endpoint, GUID: guid, USNChanged: usn}
		reader, ok := c.session.(groupMemberReader)
		if !ok {
			return ErrUnsupported
		}
		return collectGroupMemberLinks(ctx, reader, options, &result)
	})
	if err != nil {
		result.Complete = false
	}
	return result, err
}

func groupMemberVersion(object Object) (GUID, uint64, error) {
	value, err := object.Values("objectGUID").Single()
	if err != nil {
		return GUID{}, 0, err
	}
	guid, err := value.GUID()
	if err != nil {
		return GUID{}, 0, err
	}
	value, err = object.Values("uSNChanged").Single()
	if err != nil {
		return GUID{}, 0, err
	}
	text, err := value.Text()
	if err != nil {
		return GUID{}, 0, err
	}
	usn, err := strconv.ParseUint(text, 10, 64)
	return guid, usn, err
}

func collectGroupMemberLinks(ctx context.Context, reader groupMemberReader, options GroupMemberLinksOptions, result *GroupMemberLinksResult) error {
	start, remaining := uint64(0), options.MaxBytes
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if len(result.Ranges) >= options.MaxRanges || len(result.Members) >= options.MaxValues {
			return ErrGroupMembershipLimit
		}
		// Request at most 1,500 values, further narrowed by the caller's bound.
		count := min(1500, options.MaxValues-len(result.Members))
		property := fmt.Sprintf("member;range=%d-%d", start, start+uint64(count)-1)
		attributes, readErr := reader.groupMemberBaseObject(ctx, objectGUIDTarget(result.Version.GUID), []string{property, "objectGUID", "uSNChanged"}, options.IncludeTTL)
		batch := GroupMemberRange{RequestedProperty: property, Attributes: attributes, ObservedAt: time.Now().UTC(), Error: readErr}
		result.Ranges = append(result.Ranges, batch)
		// Keep the complete received response even when it exceeds a bound.
		for name, values := range attributes {
			if len(name) > remaining {
				return errors.Join(readErr, ErrGroupMembershipLimit)
			}
			remaining -= len(name)
			for _, value := range values {
				if len(value) > remaining {
					return errors.Join(readErr, ErrGroupMembershipLimit)
				}
				remaining -= len(value)
			}
		}
		values, next, terminal, present, rangeErr := groupMemberRange(attributes, start)
		result.AttributeReturned = result.AttributeReturned || present
		if len(values) > options.MaxValues-len(result.Members) {
			return errors.Join(readErr, rangeErr, ErrGroupMembershipLimit)
		}
		for _, value := range values {
			link, err := decodeGroupMemberLink(value, options.IncludeTTL, batch.ObservedAt)
			if err != nil {
				rangeErr = errors.Join(rangeErr, err)
				continue
			}
			result.Members = append(result.Members, link)
		}
		guid, usn, versionErr := groupMemberVersion(Object{Attributes: attributes})
		if versionErr == nil && (guid != result.Version.GUID || usn != result.Version.USNChanged) {
			versionErr = ErrGroupMembershipChanged
		}
		if err := errors.Join(readErr, rangeErr, versionErr); err != nil {
			return err
		}
		if terminal {
			result.Complete = true
			return nil
		}
		start = next
	}
}

func groupMemberRange(attributes map[string][][]byte, start uint64) (values [][]byte, next uint64, terminal, present bool, err error) {
	var plain [][]byte
	var rangeName string
	var plainFound bool
	for name, data := range attributes {
		lower := strings.ToLower(name)
		if lower == "member" {
			if plainFound {
				return nil, 0, false, true, ErrInvalidResult
			}
			plain, plainFound = data, true
		} else if strings.HasPrefix(lower, "member;") {
			if rangeName != "" || !strings.HasPrefix(lower, "member;range=") {
				return nil, 0, false, true, ErrInvalidResult
			}
			rangeName, values = lower, data
		}
	}
	if rangeName == "" {
		if start != 0 {
			return plain, 0, false, plainFound, ErrIncompleteResult
		}
		return plain, 0, true, plainFound, nil
	}
	if len(plain) != 0 {
		return values, 0, false, true, ErrInvalidResult
	}
	low, high, ok := strings.Cut(strings.TrimPrefix(rangeName, "member;range="), "-")
	first, parseErr := strconv.ParseUint(low, 10, 64)
	if !ok || parseErr != nil || first != start {
		return values, 0, false, true, ErrInvalidResult
	}
	if high == "*" {
		return values, 0, true, true, nil
	}
	last, parseErr := strconv.ParseUint(high, 10, 64)
	if parseErr != nil || last < first || last == ^uint64(0) || last-first != uint64(len(values))-1 || len(values) == 0 {
		return values, 0, false, true, ErrInvalidResult
	}
	return values, last + 1, false, true, nil
}

func decodeGroupMemberLink(value []byte, includeTTL bool, observed time.Time) (GroupMemberLink, error) {
	text, err := NewRawValue(value).Text()
	if err != nil {
		return GroupMemberLink{}, err
	}
	result := GroupMemberLink{Raw: text, DistinguishedName: text, ObservedAt: observed}
	if strings.HasPrefix(strings.ToLower(text), "<ttl=") {
		if !includeTTL || !strings.HasSuffix(text, ">") {
			return result, ErrInvalidResult
		}
		seconds, dn, ok := strings.Cut(text[5:len(text)-1], ",")
		ttl, err := strconv.ParseUint(seconds, 10, 64)
		if !ok || err != nil {
			return result, ErrInvalidResult
		}
		result.DistinguishedName, result.RemainingTTLSeconds = dn, &ttl
	}
	if _, err := parseIdentityDN(result.DistinguishedName); err != nil {
		return result, errors.Join(ErrInvalidResult, err)
	}
	return result, nil
}
