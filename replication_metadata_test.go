package activedirectory

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func metadataTestText(data []byte, field int, value string) []byte {
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	binary.LittleEndian.PutUint32(data[field:], uint32(len(data)))
	for _, unit := range append(utf16.Encode([]rune(value)), 0) {
		data = binary.LittleEndian.AppendUint16(data, unit)
	}
	return data
}

func metadataTestBlob(kind string) []byte {
	const ticks = uint64(133800000001234567)
	const usn = uint64(9007199254740993)
	switch kind {
	case metadataAttribute:
		data := make([]byte, 52)
		binary.LittleEndian.PutUint32(data[4:], 7)
		binary.LittleEndian.PutUint64(data[8:], ticks)
		copy(data[16:32], []byte{0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
		binary.LittleEndian.PutUint64(data[32:], usn)
		binary.LittleEndian.PutUint64(data[40:], usn+2)
		data = metadataTestText(data, 0, "description")
		return metadataTestText(data, 48, "CN=NTDS Settings,CN=DC1")
	case metadataLink:
		data := make([]byte, 80)
		binary.LittleEndian.PutUint64(data[16:], ticks+1)
		binary.LittleEndian.PutUint64(data[24:], ticks-10)
		binary.LittleEndian.PutUint32(data[32:], 3)
		binary.LittleEndian.PutUint64(data[36:], ticks)
		copy(data[44:60], metadataTestBlob(metadataAttribute)[16:32])
		binary.LittleEndian.PutUint64(data[60:], usn)
		binary.LittleEndian.PutUint64(data[68:], usn+2)
		binary.LittleEndian.PutUint32(data[8:], 3)
		binary.LittleEndian.PutUint32(data[12:], 80)
		data = append(data, 0, 255, 128)
		data = metadataTestText(data, 0, "member")
		data = metadataTestText(data, 4, "CN=Member 😀,DC=example,DC=test")
		return metadataTestText(data, 76, "CN=NTDS Settings,CN=DC1")
	default:
		data := make([]byte, 36)
		copy(data[:16], metadataTestBlob(metadataAttribute)[16:32])
		binary.LittleEndian.PutUint64(data[16:], usn)
		binary.LittleEndian.PutUint64(data[24:], ticks)
		return metadataTestText(data, 32, "CN=NTDS Settings,CN=DC1")
	}
}

func TestMetadataBinaryPreservesStampsAndWirePacking(t *testing.T) {
	attribute, err := decodeMetadataAttribute(metadataTestBlob(metadataAttribute))
	if err != nil || attribute.AttributeName != "description" || attribute.Version != 7 || attribute.OriginatingInvocationID != "00112233-4455-6677-8899-aabbccddeeff" || attribute.OriginatingUSN != 9007199254740993 || attribute.LocalUSN != 9007199254740995 || *attribute.LastOriginatingChange.Ticks != 133800000001234567 || attribute.LastOriginatingChange.UTC.Nanosecond() != 123456700 {
		t.Fatalf("attribute=%+v err=%v", attribute, err)
	}
	link, err := decodeMetadataLink(metadataTestBlob(metadataLink))
	if err != nil || link.AttributeName != "member" || link.OriginatingUSN != attribute.OriginatingUSN || link.LocalUSN != attribute.LocalUSN || link.OriginatingInvocationID != attribute.OriginatingInvocationID || link.ValueDN == nil || !strings.Contains(*link.ValueDN, "😀") || !slices.Equal(link.Data, []byte{0, 255, 128}) || *link.Deleted.Ticks != *attribute.LastOriginatingChange.Ticks+1 {
		t.Fatalf("link=%+v err=%v", link, err)
	}
	cursor, err := decodeMetadataCursor(metadataTestBlob(metadataVector))
	if err != nil || cursor.HighestUSN != attribute.OriginatingUSN || cursor.InvocationID != attribute.OriginatingInvocationID || *cursor.SourceServerDN != *attribute.OriginatingServerDN {
		t.Fatalf("cursor=%+v err=%v", cursor, err)
	}
	// Zero timestamp and missing DSA remain distinct from a successful event.
	data := metadataTestBlob(metadataAttribute)
	clear(data[8:16])
	clear(data[48:52])
	attribute, err = decodeMetadataAttribute(data)
	if err != nil || attribute.OriginatingServerDN != nil || attribute.LastOriginatingChange.UTC != nil || attribute.LastOriginatingChange.Ticks == nil || *attribute.LastOriginatingChange.Ticks != 0 {
		t.Fatal("zero/missing values conflated")
	}
}

func TestMetadataBinaryRejectsInvalidOffsetsUTF16AndTruncation(t *testing.T) {
	for _, kind := range []string{metadataAttribute, metadataLink, metadataVector} {
		decode := func(data []byte) error {
			switch kind {
			case metadataAttribute:
				_, err := decodeMetadataAttribute(data)
				return err
			case metadataLink:
				_, err := decodeMetadataLink(data)
				return err
			default:
				_, err := decodeMetadataCursor(data)
				return err
			}
		}
		original := metadataTestBlob(kind)
		for i := 0; i < len(original); i++ {
			if err := decode(original[:i]); err == nil {
				t.Fatalf("%s accepted truncation at %d", kind, i)
			}
		}
		for _, offset := range []uint32{1, 4, 0xfffffffc, 0xffffffff} {
			data := slices.Clone(original)
			field := 0
			if kind == metadataVector {
				field = 32
			}
			binary.LittleEndian.PutUint32(data[field:], offset)
			if err := decode(data); !errors.Is(err, ErrInvalidResult) {
				t.Fatalf("%s accepted invalid offset %d", kind, offset)
			}
		}
	}
	data := metadataTestBlob(metadataAttribute)
	offset := binary.LittleEndian.Uint32(data)
	binary.LittleEndian.PutUint16(data[offset:], 0xd800)
	if _, err := decodeMetadataAttribute(data); !errors.Is(err, ErrInvalidResult) {
		t.Fatal("unpaired surrogate accepted")
	}
	data = metadataTestBlob(metadataLink)
	binary.LittleEndian.PutUint32(data[8:], 0xffffffff)
	if _, err := decodeMetadataLink(data); !errors.Is(err, ErrInvalidResult) {
		t.Fatal("overflowing value accepted")
	}
}

func metadataTestDial(t *testing.T, read func(Config, string, []string) (map[string][][]byte, error), closeFn func(Config) error) func(context.Context, Config) (*Client, error) {
	return func(_ context.Context, config Config) (*Client, error) {
		return newClient(config, testSession{
			read: func(context.Context, []string) (map[string][][]byte, error) {
				return map[string][][]byte{"supportedcapabilities": {[]byte(CapabilityActiveDirectory)}, "namingcontexts": {[]byte("DC=example,DC=test")}}, nil
			},
			ranged: func(_ context.Context, base string, properties []string) (map[string][][]byte, error) {
				return read(config, base, properties)
			},
			finish: func() error {
				if closeFn != nil {
					return closeFn(config)
				}
				return nil
			},
		}), nil
	}
}

func TestMetadataPropertiesLinksAndPartialServers(t *testing.T) {
	denied := &LDAPError{Code: 50, Operation: "metadata"}
	closes := 0
	dial := metadataTestDial(t, func(config Config, base string, properties []string) (map[string][][]byte, error) {
		if base != "CN=Group,DC=example,DC=test" {
			t.Fatal("object targeting lost")
		}
		if config.Endpoint.Host == "denied.example.test" {
			return nil, denied
		}
		kind := strings.Split(properties[0], ";")[0]
		return map[string][][]byte{kind + ";binary": {metadataTestBlob(kind)}}, nil
	}, func(Config) error { closes++; return nil })
	query := ReplicationAttributeMetadataQuery{ObjectDN: "CN=Group,DC=example,DC=test", IncludeLinkedValues: true, Properties: []string{"MEMBER"}, Selection: ReplicationSelection{Servers: []Endpoint{{Host: "denied.example.test"}, {Host: "good.example.test"}}}}
	got, err := readReplicationAttributeMetadata(context.Background(), Config{Endpoint: Endpoint{Host: "good.example.test"}}, query, dial)
	if !errors.Is(err, denied) || !errors.Is(err, ErrIncompleteResult) || got.Complete || len(got.Servers) != 2 || closes != 2 {
		t.Fatalf("got=%+v err=%v closes=%d", got, err, closes)
	}
	bad, good := got.Servers[0], got.Servers[1]
	if bad.AttributesState.Complete || bad.LinkedValuesState.Available || !good.Observation.Complete || !good.AttributesState.Complete || len(good.Attributes) != 0 || len(good.LinkedValues) != 1 || len(good.Objects) != 2 {
		t.Fatalf("bad=%+v good=%+v", bad, good)
	}
}

func TestMetadataRangesPreserveFailureAndDetectConcurrentWrites(t *testing.T) {
	for _, mode := range []string{"success", "changed", "omitted-usn", "gap", "reset", "denied", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			denied := &LDAPError{Code: 50}
			dial := metadataTestDial(t, func(_ Config, _ string, properties []string) (map[string][][]byte, error) {
				calls++
				usn := "100"
				name := metadataAttribute + ";binary;range=0-0"
				var readErr error
				if calls == 2 {
					if properties[0] != metadataAttribute+";binary;range=1-*" {
						t.Fatalf("continuation=%s", properties[0])
					}
					name = metadataAttribute + ";binary;range=1-*"
					switch mode {
					case "changed":
						usn = "101"
					case "gap":
						name = metadataAttribute + ";binary;range=2-*"
					case "reset":
						name = metadataAttribute + ";binary"
					case "denied":
						readErr = denied
					}
				}
				value := metadataTestBlob(metadataAttribute)
				if mode == "malformed" && calls == 2 {
					value = []byte{1}
				}
				attrs := map[string][][]byte{name: {value}, "usnchanged": {[]byte(usn)}}
				if mode == "omitted-usn" {
					delete(attrs, "usnchanged")
				}
				return attrs, readErr
			}, nil)
			got, err := readReplicationAttributeMetadata(context.Background(), Config{Endpoint: Endpoint{Host: "dc.example.test"}}, ReplicationAttributeMetadataQuery{ObjectDN: "CN=Group,DC=example,DC=test"}, dial)
			if len(got.Servers) != 1 || len(got.Servers[0].Attributes) == 0 || !got.Servers[0].AttributesState.Available {
				t.Fatal("lost partial data")
			}
			if mode == "success" {
				if err != nil || !got.Complete || calls != 2 || len(got.Servers[0].Attributes) != 2 {
					t.Fatalf("success %+v %v", got, err)
				}
			} else if err == nil || got.Complete || got.Servers[0].AttributesState.Complete {
				t.Fatalf("failure marked complete: %+v", got)
			}
			if mode == "denied" && !errors.Is(err, denied) {
				t.Fatal("native denial lost")
			}
		})
	}
}

func TestMetadataVectorsRetainMissingPartitionAndDefaultToHostedNCs(t *testing.T) {
	missing := &LDAPError{Code: 32}
	var bases []string
	dial := metadataTestDial(t, func(_ Config, base string, _ []string) (map[string][][]byte, error) {
		bases = append(bases, base)
		if base == "DC=missing" {
			return nil, missing
		}
		return map[string][][]byte{metadataVector + ";binary": {metadataTestBlob(metadataVector)}}, nil
	}, nil)
	config := Config{Endpoint: Endpoint{Host: "dc.example.test"}}
	got, err := readReplicationVectors(context.Background(), config, ReplicationVectorQuery{PartitionDNs: []string{"DC=missing", "DC=example,DC=test"}}, dial)
	if !errors.Is(err, missing) || got.Complete || len(got.Servers) != 1 || len(got.Servers[0].Partitions) != 2 || got.Servers[0].Partitions[0].State.Complete || len(got.Servers[0].Partitions[1].Cursors) != 1 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	bases = nil
	got, err = readReplicationVectors(context.Background(), config, ReplicationVectorQuery{}, dial)
	if err != nil || !got.Complete || !reflect.DeepEqual(bases, []string{"DC=example,DC=test"}) {
		t.Fatalf("default partitions=%v err=%v", bases, err)
	}
}

func TestMetadataFailureStatesOmissionCancellationAndCleanup(t *testing.T) {
	for _, mode := range []string{"omitted", "dial", "root", "close", "control", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			sentinel := errors.New("injected failure")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			dial := func(_ context.Context, config Config) (*Client, error) {
				calls++
				if mode == "dial" {
					return nil, sentinel
				}
				return newClient(config, testSession{read: func(context.Context, []string) (map[string][][]byte, error) {
					if mode == "root" {
						return nil, sentinel
					}
					return map[string][][]byte{"supportedcapabilities": {[]byte(CapabilityActiveDirectory)}}, nil
				}, ranged: func(context.Context, string, []string) (map[string][][]byte, error) {
					if mode == "cancelled" {
						cancel()
					}
					if mode == "omitted" {
						return nil, nil
					}
					return map[string][][]byte{metadataAttribute + ";binary": {metadataTestBlob(metadataAttribute)}}, nil
				}, finish: func() error {
					if mode == "close" {
						return sentinel
					}
					return nil
				}}), nil
			}
			query := ReplicationAttributeMetadataQuery{ObjectDN: "CN=Object", IncludeDeletedObjects: mode == "control", Selection: ReplicationSelection{Servers: []Endpoint{{Host: "one.example.test"}, {Host: "two.example.test"}}}}
			got, err := readReplicationAttributeMetadata(ctx, Config{Endpoint: Endpoint{Host: "one.example.test"}, Timeout: time.Second}, query, dial)
			if err == nil || got.Complete || len(got.Servers) != 2 || got.Servers[0].Observation.Complete || got.Servers[1].Observation.Complete {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if mode == "cancelled" && (calls != 1 || !errors.Is(err, context.Canceled) || !errors.Is(got.Servers[1].Observation.Error, context.Canceled)) {
				t.Fatal("canceled target dropped or dialed")
			}
		})
	}
}

func TestMetadataQueryValidation(t *testing.T) {
	for _, query := range []ReplicationAttributeMetadataQuery{{}, {ObjectDN: "a\x00b"}, {ObjectDN: "CN=x", Properties: []string{"*", "member"}}, {ObjectDN: "CN=x", Properties: []string{"member;binary"}}, {ObjectDN: "CN=x", IncludeDeactivatedLinks: true}} {
		if err := query.validate(); err == nil {
			t.Fatalf("accepted %+v", query)
		}
	}
}

func FuzzReplicationMetadataPackets(f *testing.F) {
	for _, kind := range []string{metadataAttribute, metadataLink, metadataVector} {
		f.Add(metadataTestBlob(kind))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeMetadataAttribute(data)
		_, _ = decodeMetadataLink(data)
		_, _ = decodeMetadataCursor(data)
	})
}
