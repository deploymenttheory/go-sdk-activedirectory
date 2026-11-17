package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

type AccountAuthorizationGroupsOptions struct {
	Partition     string
	Contexts      []MembershipContext
	GlobalCatalog *Client
	Properties    []string
	Limits        admodel.MembershipLimits
}

func InternalCollectAuthorizationSIDs(
	ctx context.Context,
	home InternalMembershipEndpoint,
	account admodel.Object,
	budget *admodel.InternalMembershipBudget,
	result *admodel.AccountAuthorizationGroupsResult,
) error {
	reader, ok := home.InternalClient.session.(admodel.InternalGroupMemberReader)
	if !ok {
		return admodel.ErrUnsupported
	}
	guid, usn, err := admodel.InternalGroupMemberVersion(account)
	if err != nil {
		return err
	}
	start := uint64(0)
	seen := map[string]bool{}
	for {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		remaining := budget.InternalLimits.MaxObjects - budget.InternalObjects
		if remaining <= 0 || budget.InternalRanges >= budget.InternalLimits.MaxRanges ||
			budget.InternalBytes >= budget.InternalLimits.MaxBytes {
			return admodel.ErrMembershipLimit
		}
		property := fmt.Sprintf(
			"tokenGroups;range=%d-%d",
			start,
			start+uint64(min(1500, remaining))-1,
		)
		attributes, readErr := reader.InternalGroupMemberBaseObject(
			ctx,
			admodel.InternalObjectGUIDTarget(guid),
			[]string{property, "objectGUID", "uSNChanged"},
			false,
		)
		result.Ranges = append(
			result.Ranges,
			admodel.GroupMemberRange{
				RequestedProperty: property,
				Attributes:        attributes,
				ObservedAt:        time.Now().UTC(),
				Error:             readErr,
			},
		)
		budget.InternalRanges++
		if err := budget.InternalAttributes(attributes); err != nil {
			return errors.Join(readErr, err)
		}
		// Reuse the strict contiguous-range parser without interpreting SID
		// bytes as member DNs. Original tokenGroups descriptions remain in Ranges.
		ranges := make(map[string][][]byte)
		for name, values := range attributes {
			lower := strings.ToLower(name)
			if lower == "tokengroups" || strings.HasPrefix(lower, "tokengroups;") {
				key := "member" + lower[len("tokengroups"):]
				if _, exists := ranges[key]; exists {
					return errors.Join(readErr, admodel.ErrInvalidResult)
				}
				ranges[key] = values
			}
		}
		values, next, terminal, present, rangeErr := admodel.InternalGroupMemberRange(ranges, start)
		if !present {
			rangeErr = errors.Join(rangeErr, admodel.ErrAuthorizationGroupsUnavailable)
		}
		for _, value := range values {
			if budget.InternalObjects >= budget.InternalLimits.MaxObjects {
				return errors.Join(readErr, rangeErr, admodel.ErrMembershipLimit)
			}
			budget.InternalObjects++
			sid, err := admodel.SIDFromBytes(value)
			if err != nil {
				rangeErr = errors.Join(rangeErr, err)
				continue
			}
			if !seen[sid.String()] {
				seen[sid.String()] = true
				result.SIDs = append(result.SIDs, sid)
			}
		}
		observedGUID, observedUSN, versionErr := admodel.InternalGroupMemberVersion(
			admodel.Object{Attributes: attributes},
		)
		if versionErr == nil && (observedGUID != guid || observedUSN != usn) {
			versionErr = admodel.ErrGroupMembershipChanged
		}
		if err := errors.Join(readErr, rangeErr, versionErr); err != nil {
			return err
		}
		if terminal {
			result.TokensComplete = true
			return nil
		}
		start = next
	}
}
