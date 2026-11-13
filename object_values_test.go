package activedirectory

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestGUIDAndSIDBinaryLayouts(t *testing.T) {
	guid, err := ParseGUID("{00112233-4455-6677-8899-AABBCCDDEEFF}")
	want := []byte{0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	if err != nil || !bytes.Equal(guid.Bytes(), want) || guid.String() != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("%v %v", guid, err)
	}
	for _, bad := range []string{"", "00112233445566778899aabbccddeeff", "00112233-4455-6677-8899-aabbccddeefg", "00112233-4455-6677-8899-aabbccddeeffx"} {
		if _, err := ParseGUID(bad); err == nil {
			t.Fatal(bad)
		}
	}
	sid, err := ParseSID("S-1-5-21-4294967295")
	want = []byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 255, 255, 255, 255}
	if err != nil || !bytes.Equal(sid.Bytes(), want) || sid.String() != "S-1-5-21-4294967295" {
		t.Fatalf("%v %v", sid, err)
	}
	authority, err := ParseSID("S-1-0x010203040506-42")
	if err != nil || !bytes.Equal(authority.Bytes()[2:8], []byte{1, 2, 3, 4, 5, 6}) || authority.String() != "S-1-0x010203040506-42" {
		t.Fatalf("%v %v", authority, err)
	}
	for _, bad := range []string{"S-2-5-1", "S-1-281474976710656-1", "S-1-5-4294967296", "S-1-5--1", "S-1-+5-1", "S-1-5-+1", "S-1-5-", "BA"} {
		if _, err := ParseSID(bad); err == nil {
			t.Fatal(bad)
		}
	}
	for _, bad := range [][]byte{nil, {1, 1, 0, 0, 0, 0, 0, 5}, {2, 0, 0, 0, 0, 0, 0, 5}, {1, 16, 0, 0, 0, 0, 0, 5}} {
		if _, err := SIDFromBytes(bad); err == nil {
			t.Fatal(bad)
		}
	}
	input := sid.Bytes()
	copied, err := SIDFromBytes(input)
	clear(input)
	if err != nil || copied != sid {
		t.Fatal("SID retained mutable caller storage")
	}
}

func TestAttributeValuesKeepStateRawBytesAndMultiplicity(t *testing.T) {
	object := Object{RequestedProperties: []string{"missing", "empty", "zero", "false", "members"}, Attributes: map[string][][]byte{
		"empty": {{}}, "zero": {[]byte("0")}, "false": {[]byte("FALSE")}, "vendor": {{0, 255, 128}},
		"names": {[]byte("李"), []byte("李"), []byte("Jörg")}, "members;range=0-1": {[]byte("CN=a"), []byte("CN=b")},
	}}
	for name, want := range map[string]AttributeState{"missing": AttributeAbsent, "unrequested": AttributeUnloaded, "empty": AttributePresent, "members": AttributePartial} {
		values := object.Values(name)
		if values.State != want {
			t.Fatalf("%s state %d", name, values.State)
		}
		if want != AttributePresent {
			if _, err := values.Single(); !errors.Is(err, ErrAttributeUnavailable) {
				t.Fatal(err)
			}
		}
	}
	empty, err := object.Values("empty").Single()
	text, textErr := empty.Text()
	if err != nil || textErr != nil || text != "" || empty.Bytes() == nil {
		t.Fatal("empty value became unavailable")
	}
	zero, _ := object.Values("zero").Single()
	number, err := zero.Int64()
	if err != nil || number != 0 {
		t.Fatal("zero lost")
	}
	no, _ := object.Values("false").Single()
	truth, err := no.Bool()
	if err != nil || truth {
		t.Fatal("false lost")
	}
	raw := object.Values("vendor").Values[0]
	clear(object.Attributes["vendor"][0])
	copyBytes := raw.Bytes()
	clear(copyBytes)
	if !bytes.Equal(raw.Bytes(), []byte{0, 255, 128}) {
		t.Fatal("raw value was not independently owned")
	}
	if _, err := raw.Text(); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("invalid UTF8 became text")
	}
	names := object.Values("names")
	if len(names.Values) != 3 {
		t.Fatal("duplicates lost")
	}
	if _, err := names.Single(); !errors.Is(err, ErrInvalidValue) {
		t.Fatal("multiple values became scalar")
	}
	ranges := object.Values("members")
	if len(ranges.Values) != 0 || len(ranges.Ranges["members;range=0-1"]) != 2 {
		t.Fatal("ranged values lost")
	}
}

func TestFlagsPreserveUnknownSignedBits(t *testing.T) {
	flags, err := NewRawValue([]byte("-2147483646")).Flags32()
	if err != nil || flags != 0x80000002 || flags.LDAPString() != "-2147483646" || !flags.Has(2) {
		t.Fatalf("%x %v", flags, err)
	}
	if flags.With(4, true) != 0x80000006 || flags.With(2, false) != 0x80000000 {
		t.Fatal("unrelated bits lost")
	}
	for _, bad := range []string{"4294967296", "-2147483649", "x"} {
		if _, err := NewRawValue([]byte(bad)).Flags32(); err == nil {
			t.Fatal(bad)
		}
	}
}

func TestFileTimeAndIntervalsPreserveSentinelsAndPrecision(t *testing.T) {
	for _, value := range []FileTime{0, math.MaxInt64, math.MaxUint64} {
		parsed, err := ParseFileTime(value.LDAPString())
		if err != nil || parsed != value {
			t.Fatalf("sentinel %d: %d %v", value, parsed, err)
		}
		if _, err := value.Time(); !errors.Is(err, ErrValueSentinel) {
			t.Fatal(err)
		}
	}
	for _, value := range []FileTime{1, 116444736000000000, 133711234567890123, math.MaxInt64 - 1} {
		instant, err := value.Time()
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, err := FileTimeFromTime(instant)
		if err != nil || roundtrip != value {
			t.Fatalf("%d -> %v -> %d (%v)", value, instant, roundtrip, err)
		}
	}
	if _, err := FileTimeFromTime(time.Unix(0, 1)); !errors.Is(err, ErrValuePrecision) {
		t.Fatal(err)
	}
	if _, err := FileTimeFromTime(time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrValueRange) {
		t.Fatal(err)
	}
	if _, err := FileTime(math.MaxInt64 + 1).Time(); !errors.Is(err, ErrValueRange) {
		t.Fatal(err)
	}
	for _, value := range []Interval100ns{0, -1, 1, -864000000000, math.MinInt64, math.MaxInt64} {
		parsed, err := NewRawValue([]byte(value.LDAPString())).Interval()
		if err != nil || parsed != value {
			t.Fatal("interval bits lost")
		}
		duration, err := value.Duration()
		if value == math.MinInt64 {
			if !errors.Is(err, ErrValueSentinel) {
				t.Fatal(err)
			}
			continue
		}
		if value == math.MaxInt64 {
			if !errors.Is(err, ErrValueRange) {
				t.Fatal(err)
			}
			continue
		}
		roundtrip, backErr := Interval100nsFromDuration(duration)
		if err != nil || backErr != nil || roundtrip != value {
			t.Fatal(value, err, backErr)
		}
	}
	if _, err := Interval100nsFromDuration(time.Nanosecond); !errors.Is(err, ErrValuePrecision) {
		t.Fatal(err)
	}
}

func TestGeneralizedTimeExactFractionsZonesAndCalendar(t *testing.T) {
	for _, tc := range []struct{ wire, want string }{
		{"20240229123456.1234567Z", "2024-02-29T12:34:56.1234567Z"},
		{"20240229123456.123456789000Z", "2024-02-29T12:34:56.123456789Z"},
		{"2024022912.5Z", "2024-02-29T12:30:00Z"},
		{"202402291234,5+0130", "2024-02-29T11:04:30Z"},
		{"20240229123456-02", "2024-02-29T14:34:56Z"},
	} {
		value, err := ParseGeneralizedTime(tc.wire)
		if err != nil || value.String() != tc.wire {
			t.Fatal(tc, err)
		}
		instant, err := value.Time()
		if err != nil || instant.Format(time.RFC3339Nano) != tc.want {
			t.Fatal(tc, instant, err)
		}
	}
	for _, wire := range []string{"20240229123456.0000000001Z", "20161231235960Z"} {
		value, err := ParseGeneralizedTime(wire)
		if err != nil || value.String() != wire {
			t.Fatal(wire, err)
		}
		if _, err := value.Time(); !errors.Is(err, ErrValuePrecision) {
			t.Fatal("precision silently lost", err)
		}
	}
	for _, wire := range []string{"20230229123456Z", "20241301123456Z", "20240229243456Z", "20240229123456+2400", "20240229123456+0060", "20240229123461Z", "20240229123456.Z", "20240229123456", "bad"} {
		if _, err := ParseGeneralizedTime(wire); err == nil {
			t.Fatal(wire)
		}
	}
}

func FuzzGUIDAndSIDValues(f *testing.F) {
	f.Add([]byte{1, 1, 0, 0, 0, 0, 0, 5, 42, 0, 0, 0})
	f.Add(make([]byte, 16))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if guid, err := GUIDFromBytes(raw); err == nil {
			parsed, err := ParseGUID(guid.String())
			if err != nil || parsed != guid || !bytes.Equal(parsed.Bytes(), raw) {
				t.Fatal("GUID roundtrip")
			}
		}
		if sid, err := SIDFromBytes(raw); err == nil {
			parsed, err := ParseSID(sid.String())
			if err != nil || parsed != sid || !bytes.Equal(parsed.Bytes(), raw) {
				t.Fatal("SID roundtrip")
			}
		}
		value := NewRawValue(raw)
		if !reflect.DeepEqual(value.Bytes(), raw) {
			t.Fatal("raw bytes changed")
		}
	})
}

func FuzzDirectoryTimeValues(f *testing.F) {
	for _, seed := range []string{"20240229123456.1234567890Z", "2024022912.0000000000001Z", "-9223372036854775808", "18446744073709551615", "0", "bad"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if value, err := ParseGeneralizedTime(raw); err == nil {
			if value.String() != raw {
				t.Fatal("generalized time changed")
			}
			_, _ = value.Time()
		}
		if value, err := ParseFileTime(raw); err == nil {
			roundtrip, err := ParseFileTime(value.LDAPString())
			if err != nil || roundtrip != value {
				t.Fatal("FILETIME bits lost")
			}
		}
	})
}
