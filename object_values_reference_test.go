package activedirectory

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"testing"
)

// Opt-in differential consumption only. The SDK/test never launches PowerShell
// or contacts AD here; the explicit local collector records .NET expectations.
func TestObjectValuesPowerShellReference(t *testing.T) {
	path := os.Getenv("ADSDK_OBJECT_VALUES_REFERENCE")
	if path == "" {
		t.Skip("requires the explicit local PowerShell/.NET value reference")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil || len(data) > 1024*1024 {
		t.Fatal("cannot read bounded value reference", err)
	}
	var reference struct {
		SchemaVersion      int     `json:"schema_version"`
		Purpose            string  `json:"purpose"`
		Computer           string  `json:"computer"`
		OSVersion          string  `json:"os_version"`
		PowerShellVersion  string  `json:"powershell_version"`
		ModuleVersion      *string `json:"active_directory_module_version"`
		DirectoryContacted *bool   `json:"directory_contacted"`
		FullTicketComplete *bool   `json:"full_ticket_complete"`
		GUIDs              []struct {
			Text      string `json:"text"`
			BinaryHex string `json:"binary_hex"`
		} `json:"guids"`
		SIDs []struct {
			Text      string `json:"text"`
			BinaryHex string `json:"binary_hex"`
		} `json:"sids"`
		FileTimes []struct {
			Ticks    string  `json:"ticks"`
			Sentinel bool    `json:"sentinel"`
			UTC      *string `json:"utc"`
		} `json:"file_times"`
		Intervals []struct {
			Ticks string `json:"ticks"`
		} `json:"intervals"`
		Flags []struct {
			Signed   string `json:"signed"`
			Unsigned string `json:"unsigned"`
		} `json:"flags"`
		Generalized []struct {
			Text     string `json:"text"`
			FileTime string `json:"file_time"`
		} `json:"generalized_times"`
	}
	if err := json.Unmarshal(data, &reference); err != nil {
		t.Fatal(err)
	}
	if reference.SchemaVersion != 1 || reference.Purpose != "go-sdk-activedirectory-object-values-reference" || reference.Computer == "" || reference.OSVersion == "" || reference.PowerShellVersion == "" || reference.DirectoryContacted == nil || *reference.DirectoryContacted || reference.FullTicketComplete == nil || *reference.FullTicketComplete {
		t.Fatal("reference identity or coverage claim differs")
	}
	if len(reference.GUIDs) != 3 || len(reference.SIDs) != 3 || len(reference.FileTimes) != 6 || len(reference.Intervals) != 6 || len(reference.Flags) != 4 || len(reference.Generalized) != 2 {
		t.Fatal("incomplete differential corpus")
	}
	for _, row := range reference.GUIDs {
		value, err := ParseGUID(row.Text)
		if err != nil || hex.EncodeToString(value.Bytes()) != row.BinaryHex || value.String() != row.Text {
			t.Fatal("GUID differential mismatch", err)
		}
	}
	for _, row := range reference.SIDs {
		value, err := ParseSID(row.Text)
		if err != nil || hex.EncodeToString(value.Bytes()) != row.BinaryHex || value.String() != row.Text {
			t.Fatal("SID differential mismatch", err)
		}
	}
	for _, row := range reference.FileTimes {
		value, err := ParseFileTime(row.Ticks)
		if err != nil || value.LDAPString() != row.Ticks {
			t.Fatal("FILETIME bits differ", err)
		}
		instant, err := value.Time()
		if row.Sentinel {
			if !errors.Is(err, ErrValueSentinel) {
				t.Fatal("sentinel lost")
			}
			continue
		}
		if err != nil || row.UTC == nil || instant.Format("2006-01-02T15:04:05.0000000Z") != *row.UTC {
			t.Fatal("FILETIME timestamp differs", err)
		}
	}
	for _, row := range reference.Intervals {
		value, err := NewRawValue([]byte(row.Ticks)).Interval()
		if err != nil || value.LDAPString() != row.Ticks {
			t.Fatal("TimeSpan ticks differ", err)
		}
	}
	for _, row := range reference.Flags {
		value, err := NewRawValue([]byte(row.Signed)).Flags32()
		if err != nil || value.LDAPString() != row.Signed || strconv.FormatUint(uint64(value), 10) != row.Unsigned {
			t.Fatal("flag bits differ", err)
		}
	}
	for _, row := range reference.Generalized {
		value, err := ParseGeneralizedTime(row.Text)
		if err != nil {
			t.Fatal(err)
		}
		instant, err := value.Time()
		if err != nil {
			t.Fatal(err)
		}
		fileTime, err := FileTimeFromTime(instant)
		if err != nil || fileTime.LDAPString() != row.FileTime {
			t.Fatal("generalized time differs", err)
		}
	}
	t.Logf("local reference OS=%s PowerShell=%s AD-module-installed=%v; no directory coverage", reference.OSVersion, reference.PowerShellVersion, reference.ModuleVersion != nil)
}
