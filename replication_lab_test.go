package activedirectory

import (
	"strconv"
	"strings"
	"testing"
)

// An allowlisted differential projection; raw directory maps and credentials
// are deliberately absent. Decimal strings avoid JSON integer rounding in
// external readers. Missing fields stay null, including missing timestamps.
type replicationLabPartner struct {
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
type replicationLabFailure struct {
	Kind        string  `json:"kind"`
	Partner     *string `json:"partner"`
	PartnerGUID string  `json:"partner_guid"`
	Time        *string `json:"time"`
	Count       string  `json:"count"`
	LastResult  string  `json:"last_result"`
}
type replicationLabOperation struct {
	ID        string  `json:"id"`
	Priority  string  `json:"priority"`
	Type      string  `json:"type"`
	Options   string  `json:"options"`
	Partition *string `json:"partition"`
	Partner   *string `json:"partner"`
	Address   *string `json:"address"`
	Enqueued  *string `json:"enqueued"`
}
type replicationLabServer struct {
	Server       string                    `json:"server"`
	Partners     []replicationLabPartner   `json:"partners"`
	Failures     []replicationLabFailure   `json:"failures"`
	Queue        []replicationLabOperation `json:"queue"`
	QueueStarted *string                   `json:"queue_started"`
	Errors       map[string]string         `json:"errors"`
}

func replicationLabText(value *string) *string {
	if value == nil || *value == "" {
		return nil
	}
	copy := strings.ToLower(*value)
	return &copy
}
func replicationLabNumber[T ~uint32 | ~uint64 | ~int64](value *T) *string {
	if value == nil {
		return nil
	}
	text := strconv.FormatInt(int64(*value), 10)
	if *value >= 0 {
		text = strconv.FormatUint(uint64(*value), 10)
	}
	return &text
}
func replicationLabPartners(rows []ReplicationPartner) []replicationLabPartner {
	result := make([]replicationLabPartner, 0, len(rows))
	for _, row := range rows {
		direction := "inbound"
		if row.Direction == ReplicationOutbound {
			direction = "outbound"
		}
		result = append(result, replicationLabPartner{Direction: direction, Partition: replicationLabText(row.PartitionDN), Partner: replicationLabText(row.PartnerDN), Address: replicationLabText(row.PartnerAddress), PartnerGUID: replicationLabText(row.PartnerGUID), PartitionGUID: replicationLabText(row.PartitionGUID), InvocationGUID: replicationLabText(row.InvocationID), LastAttempt: replicationLabNumber(row.LastAttempt.Ticks), LastSuccess: replicationLabNumber(row.LastSuccess.Ticks), LastResult: replicationLabNumber(row.LastResult), Failures: replicationLabNumber(row.ConsecutiveFailures), USNFilter: replicationLabNumber(row.AttributeFilterUSN)})
	}
	return result
}
func replicationLabFailures(rows []ReplicationFailure) []replicationLabFailure {
	result := make([]replicationLabFailure, 0, len(rows))
	for _, row := range rows {
		kind := "connection"
		if row.Kind == ReplicationLinkFailure {
			kind = "link"
		}
		result = append(result, replicationLabFailure{Kind: kind, Partner: replicationLabText(row.PartnerDN), PartnerGUID: strings.ToLower(row.PartnerGUID), Time: replicationLabNumber(row.Time.Ticks), Count: strconv.FormatUint(uint64(row.FailureCount), 10), LastResult: strconv.FormatUint(uint64(row.LastResult), 10)})
	}
	return result
}
func replicationLabQueue(rows []ReplicationQueueOperation) []replicationLabOperation {
	result := make([]replicationLabOperation, 0, len(rows))
	for _, row := range rows {
		result = append(result, replicationLabOperation{ID: strconv.FormatUint(uint64(row.SerialNumber), 10), Priority: strconv.FormatUint(uint64(row.Priority), 10), Type: strconv.FormatUint(uint64(row.Type), 10), Options: strconv.FormatUint(uint64(row.Options), 10), Partition: replicationLabText(row.PartitionDN), Partner: replicationLabText(row.PartnerDN), Address: replicationLabText(row.PartnerAddress), Enqueued: replicationLabNumber(row.Enqueued.Ticks)})
	}
	return result
}

func TestReplicationLabProjectionPreservesNumericAndMissingStates(t *testing.T) {
	zero := uint64(0)
	large := uint64(18446744073709551615)
	code := uint32(0xffffffff)
	usn := int64(-1)
	rows := replicationLabPartners([]ReplicationPartner{{Direction: ReplicationOutbound, LastSuccess: ReplicationTimestamp{Ticks: &zero}, LastAttempt: ReplicationTimestamp{Ticks: &large}, LastResult: &code, AttributeFilterUSN: &usn}})
	if len(rows) != 1 || rows[0].InvocationGUID != nil || *rows[0].LastSuccess != "0" || *rows[0].LastAttempt != "18446744073709551615" || *rows[0].LastResult != "4294967295" || *rows[0].USNFilter != "-1" {
		t.Fatalf("projection lost raw/missing semantics: %+v", rows)
	}
	queue := replicationLabQueue([]ReplicationQueueOperation{{SerialNumber: 0xffffffff, Type: 99, Options: 0x80000000}})
	if queue[0].ID != "4294967295" || queue[0].Type != "99" || queue[0].Options != "2147483648" || queue[0].Enqueued != nil {
		t.Fatalf("queue projection=%+v", queue)
	}
}
