package acceptance

import (
	"strconv"
	"strings"
	"testing"

	admodel "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/internal/model"
)

// An allowlisted differential projection; raw directory maps and credentials
// are deliberately absent. Decimal strings avoid JSON integer rounding in
// external readers. Missing fields stay null, including missing timestamps.
type InternalReplicationLabPartner struct {
	Direction      string  `json:"direction"`
	Partition      *string `json:"partition"`
	Partner        *string `json:"partner"`
	Address        *string `json:"address"`
	PartnerGUID    *string `json:"partner_guid"`
	PartitionGUID  *string `json:"partition_guid"`
	InvocationGUID *string `json:"invocation_guid"`
	LastAttempt    *string `json:"last_attempt"`
	LastSuccess    *string `json:"last_success"`
	LastResult     *string `json:"last_result"`
	Failures       *string `json:"failures"`
	USNFilter      *string `json:"usn_filter"`
}
type InternalReplicationLabFailure struct {
	Kind        string  `json:"kind"`
	Partner     *string `json:"partner"`
	PartnerGUID string  `json:"partner_guid"`
	Time        *string `json:"time"`
	Count       string  `json:"count"`
	LastResult  string  `json:"last_result"`
}
type InternalReplicationLabOperation struct {
	ID        string  `json:"id"`
	Priority  string  `json:"priority"`
	Type      string  `json:"type"`
	Options   string  `json:"options"`
	Partition *string `json:"partition"`
	Partner   *string `json:"partner"`
	Address   *string `json:"address"`
	Enqueued  *string `json:"enqueued"`
}
type InternalReplicationLabServer struct {
	Server       string                            `json:"server"`
	Partners     []InternalReplicationLabPartner   `json:"partners"`
	Failures     []InternalReplicationLabFailure   `json:"failures"`
	Queue        []InternalReplicationLabOperation `json:"queue"`
	QueueStarted *string                           `json:"queue_started"`
	Errors       map[string]string                 `json:"errors"`
}

func InternalReplicationLabText(value *string) *string {
	if value == nil || *value == "" {
		return nil
	}
	copy := strings.ToLower(*value)
	return &copy
}

func InternalReplicationLabNumber[T ~uint32 | ~uint64 | ~int64](value *T) *string {
	if value == nil {
		return nil
	}
	text := strconv.FormatInt(int64(*value), 10)
	if *value >= 0 {
		text = strconv.FormatUint(uint64(*value), 10)
	}
	return &text
}

func InternalReplicationLabPartners(
	rows []admodel.ReplicationPartner,
) []InternalReplicationLabPartner {
	result := make([]InternalReplicationLabPartner, 0, len(rows))
	for _, row := range rows {
		direction := "inbound"
		if row.Direction == admodel.ReplicationOutbound {
			direction = "outbound"
		}
		result = append(
			result,
			InternalReplicationLabPartner{
				Direction:      direction,
				Partition:      InternalReplicationLabText(row.PartitionDN),
				Partner:        InternalReplicationLabText(row.PartnerDN),
				Address:        InternalReplicationLabText(row.PartnerAddress),
				PartnerGUID:    InternalReplicationLabText(row.PartnerGUID),
				PartitionGUID:  InternalReplicationLabText(row.PartitionGUID),
				InvocationGUID: InternalReplicationLabText(row.InvocationID),
				LastAttempt:    InternalReplicationLabNumber(row.LastAttempt.Ticks),
				LastSuccess:    InternalReplicationLabNumber(row.LastSuccess.Ticks),
				LastResult:     InternalReplicationLabNumber(row.LastResult),
				Failures:       InternalReplicationLabNumber(row.ConsecutiveFailures),
				USNFilter:      InternalReplicationLabNumber(row.AttributeFilterUSN),
			},
		)
	}
	return result
}

func InternalReplicationLabFailures(
	rows []admodel.ReplicationFailure,
) []InternalReplicationLabFailure {
	result := make([]InternalReplicationLabFailure, 0, len(rows))
	for _, row := range rows {
		kind := "connection"
		if row.Kind == admodel.ReplicationLinkFailure {
			kind = "link"
		}
		result = append(
			result,
			InternalReplicationLabFailure{
				Kind:        kind,
				Partner:     InternalReplicationLabText(row.PartnerDN),
				PartnerGUID: strings.ToLower(row.PartnerGUID),
				Time:        InternalReplicationLabNumber(row.Time.Ticks),
				Count:       strconv.FormatUint(uint64(row.FailureCount), 10),
				LastResult:  strconv.FormatUint(uint64(row.LastResult), 10),
			},
		)
	}
	return result
}

func InternalReplicationLabQueue(
	rows []admodel.ReplicationQueueOperation,
) []InternalReplicationLabOperation {
	result := make([]InternalReplicationLabOperation, 0, len(rows))
	for _, row := range rows {
		result = append(
			result,
			InternalReplicationLabOperation{
				ID:        strconv.FormatUint(uint64(row.SerialNumber), 10),
				Priority:  strconv.FormatUint(uint64(row.Priority), 10),
				Type:      strconv.FormatUint(uint64(row.Type), 10),
				Options:   strconv.FormatUint(uint64(row.Options), 10),
				Partition: InternalReplicationLabText(row.PartitionDN),
				Partner:   InternalReplicationLabText(row.PartnerDN),
				Address:   InternalReplicationLabText(row.PartnerAddress),
				Enqueued:  InternalReplicationLabNumber(row.Enqueued.Ticks),
			},
		)
	}
	return result
}

func TestReplicationLabProjectionPreservesNumericAndMissingStates(t *testing.T) {
	zero := uint64(0)
	large := uint64(18446744073709551615)
	code := uint32(0xffffffff)
	usn := int64(-1)
	rows := InternalReplicationLabPartners(
		[]admodel.ReplicationPartner{
			{
				Direction:          admodel.ReplicationOutbound,
				LastSuccess:        admodel.ReplicationTimestamp{Ticks: &zero},
				LastAttempt:        admodel.ReplicationTimestamp{Ticks: &large},
				LastResult:         &code,
				AttributeFilterUSN: &usn,
			},
		},
	)
	if len(rows) != 1 || rows[0].InvocationGUID != nil || *rows[0].LastSuccess != "0" ||
		*rows[0].LastAttempt != "18446744073709551615" ||
		*rows[0].LastResult != "4294967295" ||
		*rows[0].USNFilter != "-1" {
		t.Fatalf("projection lost raw/missing semantics: %+v", rows)
	}
	queue := InternalReplicationLabQueue(
		[]admodel.ReplicationQueueOperation{
			{SerialNumber: 0xffffffff, Type: 99, Options: 0x80000000},
		},
	)
	if queue[0].ID != "4294967295" || queue[0].Type != "99" || queue[0].Options != "2147483648" ||
		queue[0].Enqueued != nil {
		t.Fatalf("queue projection=%+v", queue)
	}
}
