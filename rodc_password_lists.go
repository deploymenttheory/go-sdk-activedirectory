package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Revealed entries are per-secret-attribute markers, not secret values. Several
// markers can name one account. Authenticated entries have SecretAttribute empty.
type RODCPasswordReplicationEntry struct {
	Raw                                RawValue
	DistinguishedName, SecretAttribute string
	Observation                        IdentityResult
	Error                              error
}

// Complete covers contiguous ranges and resolution of the returned references.
// Omission is retained in AttributeReturned; it does not prove ACL visibility.
// Principals are deduplicated by GUID; Entries preserve every raw linked value.
type RODCPasswordReplicationResult struct {
	Controller                                IdentityResult
	Attribute                                 string
	Entries                                   []RODCPasswordReplicationEntry
	Principals                                []MembershipPrincipal
	Ranges                                    []GroupMemberRange
	AttributeReturned, Complete, LimitReached bool
}

func (c *Client) RODCPasswordReplicationPolicy(ctx context.Context, controller Identity, list RODCPasswordReplicationList, options RODCPasswordReplicationOptions) (RODCPasswordReplicationResult, error) {
	attribute, err := list.attribute()
	if err != nil {
		return RODCPasswordReplicationResult{}, err
	}
	return c.rodcPasswordLinks(ctx, controller, attribute, false, options)
}
func (c *Client) RODCPasswordReplicationPolicyUsage(ctx context.Context, controller Identity, kind RODCPasswordReplicationUsageKind, options RODCPasswordReplicationOptions) (RODCPasswordReplicationResult, error) {
	switch kind {
	case RODCPasswordRevealed:
		return c.rodcPasswordLinks(ctx, controller, "msDS-RevealedList", true, options)
	case RODCPasswordAuthenticated:
		return c.rodcPasswordLinks(ctx, controller, "msDS-AuthenticatedToAccountlist", false, options)
	default:
		return RODCPasswordReplicationResult{}, ErrInvalidRODCPasswordPolicy
	}
}

func (c *Client) rodcPasswordLinks(ctx context.Context, controller Identity, attribute string, revealed bool, options RODCPasswordReplicationOptions) (result RODCPasswordReplicationResult, err error) {
	if options.Limits.MaxGroups != 0 || options.Limits.MaxDepth != 0 {
		return result, ErrInvalidRODCPasswordPolicy
	}
	limits, err := normalizeMembershipLimits(options.Limits)
	if err != nil {
		return result, err
	}
	if err = validateIdentityOperation(controller, membershipResolveOptions(controller, options.Partition, options.Properties)); err != nil {
		return result, err
	}
	result.Attribute = attribute
	if c == nil || c.session == nil {
		return result, ErrClosed
	}
	err = c.read(ctx, func(ctx context.Context) error {
		root, readErr := readIdentityRoot(ctx, c.session)
		if readErr != nil {
			return readErr
		}
		result.Controller, readErr = resolveIdentitySession(ctx, c.session, c.config, root, controller, membershipResolveOptions(controller, options.Partition, rodcPasswordProperties(nil)))
		if readErr != nil {
			return readErr
		}
		if err := rodcPasswordServer(ctx, c, c.session, root, result.Controller.Partition, false); err != nil {
			return err
		}
		if err := validateRODCPasswordTarget(*result.Controller.Object); err != nil {
			return err
		}
		budget := membershipBudget{limits: limits}
		if err := budget.object(*result.Controller.Object); err != nil {
			return err
		}
		rangeErr := collectRODCPasswordLinks(ctx, c.session, attribute, revealed, *result.Controller.Object, &budget, &result)
		if rangeErr != nil {
			return rangeErr
		}
		seen := map[GUID]bool{}
		var failures []error
		for i := range result.Entries {
			entry := &result.Entries[i]
			if budget.objects >= limits.MaxObjects || budget.bytes >= limits.MaxBytes {
				return errors.Join(append(failures, ErrMembershipLimit)...)
			}
			identity, parseErr := IdentityByDN(entry.DistinguishedName)
			if parseErr != nil {
				return parseErr
			}
			observed, resolveErr := resolveIdentitySession(ctx, c.session, c.config, root, identity, membershipResolveOptions(identity, result.Controller.Partition, append([]string{"groupType"}, options.Properties...)))
			entry.Observation = observed
			for _, object := range observed.Candidates {
				resolveErr = errors.Join(resolveErr, budget.object(object))
			}
			if resolveErr == nil {
				object := *observed.Object
				if principalErr := validateRODCPasswordPrincipal(object, attribute != "msDS-AuthenticatedToAccountlist" && !revealed); principalErr != nil {
					resolveErr = principalErr
				} else {
					principal, decodeErr := decodeMembershipPrincipal(object, c.config.Endpoint)
					resolveErr = decodeErr
					if decodeErr == nil && !seen[principal.GUID] {
						seen[principal.GUID] = true
						result.Principals = append(result.Principals, principal)
					}
				}
			}
			entry.Error = resolveErr
			if resolveErr != nil {
				failures = append(failures, resolveErr)
				if errors.Is(resolveErr, ErrMembershipLimit) {
					break
				}
			}
		}
		return errors.Join(failures...)
	})
	result.Complete = err == nil
	result.LimitReached = errors.Is(err, ErrMembershipLimit)
	return result, rodcPasswordError(err)
}

func collectRODCPasswordLinks(ctx context.Context, session directorySession, attribute string, revealed bool, object Object, budget *membershipBudget, result *RODCPasswordReplicationResult) error {
	reader, ok := session.(groupMemberReader)
	if !ok {
		return ErrUnsupported
	}
	guid, usn, err := groupMemberVersion(object)
	if err != nil {
		return err
	}
	start := uint64(0)
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		remaining := budget.limits.MaxObjects - budget.objects
		if remaining <= 0 || budget.ranges >= budget.limits.MaxRanges || budget.bytes >= budget.limits.MaxBytes {
			return ErrMembershipLimit
		}
		property := fmt.Sprintf("%s;range=%d-%d", attribute, start, start+uint64(min(1500, remaining))-1)
		attrs, readErr := reader.groupMemberBaseObject(ctx, objectGUIDTarget(guid), []string{property, "objectGUID", "uSNChanged"}, false)
		result.Ranges = append(result.Ranges, GroupMemberRange{RequestedProperty: property, Attributes: attrs, ObservedAt: time.Now().UTC(), Error: readErr})
		budget.ranges++
		if err := budget.attributes(attrs); err != nil {
			return errors.Join(readErr, err)
		}
		mapped := map[string][][]byte{}
		for name, values := range attrs {
			lower := strings.ToLower(name)
			prefix := strings.ToLower(attribute)
			if lower == prefix || strings.HasPrefix(lower, prefix+";") {
				key := "member" + lower[len(prefix):]
				if _, exists := mapped[key]; exists {
					return errors.Join(readErr, ErrInvalidResult)
				}
				mapped[key] = values
			}
		}
		values, next, terminal, present, rangeErr := groupMemberRange(mapped, start)
		result.AttributeReturned = result.AttributeReturned || present
		for _, value := range values {
			entry, decodeErr := decodeRODCPasswordLink(value, revealed)
			entry.Error = decodeErr
			result.Entries = append(result.Entries, entry)
			rangeErr = errors.Join(rangeErr, decodeErr)
			if budget.objects >= budget.limits.MaxObjects {
				return errors.Join(readErr, rangeErr, ErrMembershipLimit)
			}
			budget.objects++
		}
		observedGUID, observedUSN, versionErr := groupMemberVersion(Object{Attributes: attrs})
		if versionErr == nil && (observedGUID != guid || observedUSN != usn) {
			versionErr = ErrGroupMembershipChanged
		}
		if err := errors.Join(readErr, rangeErr, versionErr); err != nil {
			return err
		}
		if terminal {
			return nil
		}
		start = next
	}
}

func decodeRODCPasswordLink(value []byte, revealed bool) (result RODCPasswordReplicationEntry, err error) {
	result.Raw = NewRawValue(value)
	text, err := result.Raw.Text()
	if err != nil {
		return result, err
	}
	result.DistinguishedName = text
	if revealed {
		parts := strings.SplitN(text, ":", 4)
		if len(parts) != 4 || parts[0] != "S" {
			return result, ErrInvalidResult
		}
		count, parseErr := strconv.ParseUint(parts[1], 10, 32)
		// LDAP display names are ASCII. Their byte and character counts coincide.
		if parseErr != nil || count != uint64(len(parts[2])) || !objectAttributeName(parts[2]) {
			return result, ErrInvalidResult
		}
		result.SecretAttribute, result.DistinguishedName = parts[2], parts[3]
	}
	_, err = parseIdentityDN(result.DistinguishedName)
	return result, err
}
