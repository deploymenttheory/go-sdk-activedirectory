package activedirectory

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type metadataReference struct {
	SchemaVersion                                                       int
	RunID, FixtureID, Phase, Server, ServerVersion, ServerVersionSource string
	Port                                                                uint16
	ModuleVersion, CollectorOS, IdentitySID                             string
	CollectedUTC                                                        time.Time
	Kind, ObjectDN, PartitionDN                                         string
	Properties                                                          []string
	IncludeLinkedValues, IncludeDeletedObjects                          bool
	ExpectedOutcome                                                     string
	ExpectedLDAPCodes                                                   []uint32
	ReferenceError                                                      *struct{ Type, ID string }
	Stamps                                                              []metadataReferenceStamp
	Cursors                                                             []metadataReferenceCursor
}

type metadataReferenceStamp struct {
	AttributeName                            string
	Link                                     bool
	ValueDN                                  *string
	Version                                  uint32
	InvocationID, OriginatingUSN, LocalUSN   string
	OriginatingServerDN                      *string
	ChangedTicks, CreatedTicks, DeletedTicks string
}

type metadataReferenceCursor struct {
	InvocationID, HighestUSN, LastSuccessTicks string
	SourceServerDN                             *string
}

func metadataReferenceText(value *string) *string {
	if value == nil || *value == "" {
		return nil
	}
	lower := strings.ToLower(*value)
	return &lower
}

func metadataReferenceTicks(value ReplicationTimestamp) string {
	if value.Ticks == nil {
		return ""
	}
	return strconv.FormatUint(*value.Ticks, 10)
}

func metadataStampFact(value ReplicationAttributeMetadata) metadataReferenceStamp {
	return metadataReferenceStamp{AttributeName: strings.ToLower(value.AttributeName), Version: value.Version, InvocationID: strings.ToLower(value.OriginatingInvocationID), OriginatingUSN: strconv.FormatInt(value.OriginatingUSN, 10), LocalUSN: strconv.FormatInt(value.LocalUSN, 10), OriginatingServerDN: metadataReferenceText(value.OriginatingServerDN), ChangedTicks: metadataReferenceTicks(value.LastOriginatingChange)}
}

func metadataAttributeFacts(result ReplicationAttributeMetadataServer) []metadataReferenceStamp {
	values := []metadataReferenceStamp{}
	for _, row := range result.Attributes {
		values = append(values, metadataStampFact(row))
	}
	for _, row := range result.LinkedValues {
		value := metadataStampFact(row.ReplicationAttributeMetadata)
		value.Link = true
		value.ValueDN = metadataReferenceText(row.ValueDN)
		value.CreatedTicks = metadataReferenceTicks(row.Created)
		value.DeletedTicks = metadataReferenceTicks(row.Deleted)
		values = append(values, value)
	}
	return values
}

func metadataCursorFacts(result ReplicationVectorPartition) []metadataReferenceCursor {
	values := []metadataReferenceCursor{}
	for _, row := range result.Cursors {
		values = append(values, metadataReferenceCursor{InvocationID: strings.ToLower(row.InvocationID), HighestUSN: strconv.FormatInt(row.HighestUSN, 10), LastSuccessTicks: metadataReferenceTicks(row.LastSuccess), SourceServerDN: metadataReferenceText(row.SourceServerDN)})
	}
	return values
}

// Sort canonical JSON rows, preserving duplicates and exact decimal counters.
// A duplicate or missing row must fail the comparison, never disappear in a map.
func metadataCanonical[T any](rows []T) []string {
	result := make([]string, 0, len(rows))
	for _, row := range rows {
		encoded, _ := json.Marshal(row)
		result = append(result, string(encoded))
	}
	slices.Sort(result)
	return result
}

func validateMetadataReference(ref metadataReference) error {
	if ref.SchemaVersion != 1 || ref.RunID == "" || ref.FixtureID == "" || ref.Phase == "" || ref.ServerVersion == "" || ref.ServerVersionSource == "" || ref.ModuleVersion == "" || ref.CollectorOS == "" || ref.IdentitySID == "" || ref.CollectedUTC.IsZero() || ref.Port == 0 {
		return fmt.Errorf("reference identity/version fields are required")
	}
	if err := (Config{Endpoint: Endpoint{Host: ref.Server, Port: ref.Port}}).Validate(); err != nil {
		return err
	}
	switch ref.Kind {
	case "attributes":
		if err := (ReplicationAttributeMetadataQuery{ObjectDN: ref.ObjectDN, Properties: ref.Properties, IncludeLinkedValues: ref.IncludeLinkedValues, IncludeDeletedObjects: ref.IncludeDeletedObjects}).validate(); err != nil {
			return err
		}
		if len(ref.Cursors) != 0 {
			return ErrInvalidResult
		}
	case "vectors":
		if ref.PartitionDN == "" || !validDirectoryText(ref.PartitionDN) || len(ref.Stamps) != 0 {
			return ErrInvalidResult
		}
	default:
		return ErrInvalidResult
	}
	count := len(ref.Stamps) + len(ref.Cursors)
	switch ref.ExpectedOutcome {
	case "success":
		if ref.ReferenceError != nil || count == 0 {
			return ErrInvalidResult
		}
	case "failure":
		if ref.ReferenceError == nil || ref.ReferenceError.Type == "" || len(ref.ExpectedLDAPCodes) == 0 || count != 0 {
			return ErrInvalidResult
		}
		for _, code := range ref.ExpectedLDAPCodes {
			if code == 0 {
				return ErrInvalidResult
			}
		}
	case "unavailable":
		if ref.ReferenceError != nil || count != 0 {
			return ErrInvalidResult
		}
	default:
		return ErrInvalidResult
	}
	return nil
}

func TestMetadataReferenceComparisonPreservesPrecisionAndMultiplicity(t *testing.T) {
	attribute, _ := decodeMetadataAttribute(metadataTestBlob(metadataAttribute))
	link, _ := decodeMetadataLink(metadataTestBlob(metadataLink))
	rows := metadataAttributeFacts(ReplicationAttributeMetadataServer{Attributes: []ReplicationAttributeMetadata{attribute}, LinkedValues: []ReplicationLinkedValueMetadata{link}})
	if rows[0].OriginatingUSN != "9007199254740993" || rows[0].ChangedTicks != "133800000001234567" || rows[1].DeletedTicks != "133800000001234568" || !rows[1].Link {
		t.Fatalf("lost comparison data: %+v", rows)
	}
	reordered := []metadataReferenceStamp{rows[1], rows[0]}
	if !reflect.DeepEqual(metadataCanonical(rows), metadataCanonical(reordered)) {
		t.Fatal("ordering affects equality")
	}
	reordered = append(reordered, rows[0])
	if reflect.DeepEqual(metadataCanonical(rows), metadataCanonical(reordered)) {
		t.Fatal("duplicate hidden")
	}
	reordered = slices.Clone(rows)
	reordered[0].OriginatingUSN = "9007199254740992"
	if reflect.DeepEqual(metadataCanonical(rows), metadataCanonical(reordered)) {
		t.Fatal("USN precision lost")
	}
}

func TestMetadataReferenceValidationRejectsUnqualifiedOutcomes(t *testing.T) {
	stamp, _ := decodeMetadataAttribute(metadataTestBlob(metadataAttribute))
	valid := metadataReference{SchemaVersion: 1, RunID: "run", FixtureID: "fixture", Phase: "after-write", Server: "dc.example.test", Port: 389, ServerVersion: "Server 2022", ServerVersionSource: "fixture inventory", ModuleVersion: "1.0", CollectorOS: "Windows", IdentitySID: "S-1-5-21-1", CollectedUTC: time.Now(), Kind: "attributes", ObjectDN: "CN=Object", ExpectedOutcome: "success", Stamps: []metadataReferenceStamp{metadataStampFact(stamp)}}
	if err := validateMetadataReference(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*metadataReference){
		func(r *metadataReference) { r.ServerVersion = "" },
		func(r *metadataReference) { r.IdentitySID = "" },
		func(r *metadataReference) { r.Kind = "unknown" },
		func(r *metadataReference) { r.Stamps = nil },
		func(r *metadataReference) { r.ExpectedOutcome = "unavailable" },
		func(r *metadataReference) { r.ExpectedOutcome = "failure" },
		func(r *metadataReference) {
			r.ExpectedOutcome = "failure"
			r.Stamps = nil
			r.ReferenceError = &struct{ Type, ID string }{Type: "denied"}
			r.ExpectedLDAPCodes = []uint32{0}
		},
	} {
		candidate := valid
		mutation(&candidate)
		if err := validateMetadataReference(candidate); err == nil {
			t.Fatalf("accepted malformed reference: %+v", candidate)
		}
	}
}
