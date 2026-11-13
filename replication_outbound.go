package activedirectory

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"
)

// Range ordering is meaningful only on the same connection and while values
// do not change. Validate each continuation; never merge a gap or reset into a
// purported complete collection. Raw responses remain in OutboundObjects.
func replicationRange(attributes map[string][][]byte, attribute string, start uint64) (values [][]byte, next uint64, terminal bool, err error) {
	var rangeName string
	for name, rows := range attributes {
		if strings.HasPrefix(strings.ToLower(name), attribute+";range=") {
			if rangeName != "" {
				return values, 0, false, ErrInvalidResult
			}
			rangeName = name
			values = rows
		}
	}
	if rangeName == "" {
		values = attributes[attribute]
		if start != 0 {
			return nil, 0, false, ErrIncompleteResult
		}
		if len(values) == 0 {
			return nil, 0, false, fmt.Errorf("%w: outbound replication values were omitted; empty, denied and unavailable cannot be distinguished", ErrIncompleteResult)
		}
		return values, 0, true, nil
	}
	if len(attributes[attribute]) != 0 {
		return values, 0, false, ErrInvalidResult
	}
	text := strings.TrimPrefix(strings.ToLower(rangeName), attribute+";range=")
	low, high, ok := strings.Cut(text, "-")
	if !ok {
		return values, 0, false, ErrInvalidResult
	}
	first, parseErr := strconv.ParseUint(low, 10, 32)
	if parseErr != nil || first != start {
		return nil, 0, false, ErrIncompleteResult
	}
	if high == "*" {
		if len(values) == 0 {
			return values, 0, false, ErrIncompleteResult
		}
		return values, 0, true, nil
	}
	last, parseErr := strconv.ParseUint(high, 10, 32)
	if parseErr != nil || last < first || last-first+1 != uint64(len(values)) {
		return values, 0, false, ErrIncompleteResult
	}
	return values, last + 1, false, nil
}

func decodeOutboundPartner(raw []byte) (ReplicationPartner, error) {
	result := ReplicationPartner{Direction: ReplicationOutbound}
	var wire struct {
		XMLName xml.Name
		Text    string `xml:",chardata"`
		Fields  []struct {
			XMLName  xml.Name
			Text     string     `xml:",chardata"`
			Children []struct{} `xml:",any"`
		} `xml:",any"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&wire); err != nil || wire.XMLName.Local != "DS_REPL_NEIGHBORW" || wire.XMLName.Space != "" || strings.TrimSpace(wire.Text) != "" {
		return result, ErrInvalidResult
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, ErrInvalidResult
		}
		if text, ok := token.(xml.CharData); !ok || len(bytes.TrimSpace(text)) != 0 {
			return result, ErrInvalidResult
		}
	}
	fields := map[string]string{}
	for _, field := range wire.Fields {
		if _, duplicate := fields[field.XMLName.Local]; duplicate || field.XMLName.Space != "" || len(field.Children) != 0 {
			return result, ErrInvalidResult
		}
		fields[field.XMLName.Local] = field.Text
	}
	var failures []error
	for _, field := range []struct {
		name   string
		target **string
	}{{"pszNamingContext", &result.PartitionDN}, {"pszSourceDsaDN", &result.PartnerDN}, {"pszSourceDsaAddress", &result.PartnerAddress}} {
		if value, ok := fields[field.name]; ok {
			if !validDirectoryText(value) {
				failures = append(failures, ErrInvalidResult)
			} else {
				*field.target = &value
			}
		}
	}
	for _, field := range []struct {
		name   string
		target **string
	}{{"uuidNamingContextObjGuid", &result.PartitionGUID}, {"uuidSourceDsaObjGuid", &result.PartnerGUID}} {
		if value, ok := fields[field.name]; ok {
			guid, err := replicationGUID(value)
			if err != nil {
				failures = append(failures, err)
			} else {
				*field.target = &guid
			}
		}
	}
	for _, field := range []struct {
		name   string
		target **uint32
	}{{"dwReplicaFlags", &result.ReplicaFlags}, {"dwLastSyncResult", &result.LastResult}, {"cNumConsecutiveSyncFailures", &result.ConsecutiveFailures}} {
		if value, ok := fields[field.name]; ok {
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				failures = append(failures, ErrInvalidResult)
			} else {
				n := uint32(parsed)
				*field.target = &n
			}
		}
	}
	for _, field := range []struct {
		name   string
		target *ReplicationTimestamp
	}{{"ftimeLastSyncSuccess", &result.LastSuccess}, {"ftimeLastSyncAttempt", &result.LastAttempt}} {
		if value, ok := fields[field.name]; ok {
			var err error
			*field.target, err = replicationXMLTime(value)
			failures = append(failures, err)
		}
	}
	if result.PartitionDN == nil || *result.PartitionDN == "" || result.PartnerGUID == nil {
		failures = append(failures, ErrInvalidResult)
	}
	return result, errors.Join(failures...)
}

func replicationGUID(text string) (string, error) {
	if len(text) == 38 && text[0] == '{' && text[37] == '}' {
		text = text[1:37]
	}
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return "", ErrInvalidResult
	}
	if _, err := hex.DecodeString(strings.ReplaceAll(text, "-", "")); err != nil {
		return "", ErrInvalidResult
	}
	return strings.ToLower(text), nil
}

func replicationXMLTime(text string) (ReplicationTimestamp, error) {
	value, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || !strings.HasSuffix(text, "Z") || value.Nanosecond()%100 != 0 {
		return ReplicationTimestamp{}, ErrInvalidResult
	}
	seconds := value.Unix() + 11644473600
	if seconds < 0 || uint64(seconds) > (math.MaxUint64-uint64(value.Nanosecond()/100))/10000000 {
		return ReplicationTimestamp{}, ErrInvalidResult
	}
	return replicationTicks(uint64(seconds)*10000000 + uint64(value.Nanosecond()/100)), nil
}
