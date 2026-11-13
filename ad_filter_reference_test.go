package activedirectory

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Captured from the explicitly invoked offline module collector. Normal tests
// neither launch PowerShell nor contact a directory. Raw reference output is
// retained alongside narrowly documented syntax normalization, not overwritten.
func TestADFilterOfflineModuleReference(t *testing.T) {
	data, err := os.ReadFile("testdata/ad-filter-reference.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 1024*1024 {
		t.Fatal("unexpected reference size")
	}
	var reference struct {
		Schema             int    `json:"schema_version"`
		DirectoryContacted *bool  `json:"directory_contacted"`
		Complete           *bool  `json:"full_ticket_complete"`
		Module             string `json:"module_version"`
		Assembly           string `json:"assembly_file_version"`
		Cases              []struct {
			Expression string `json:"expression"`
			Profile    string `json:"profile"`
			Variables  map[string]struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			} `json:"variables"`
			LDAP       string `json:"ldap"`
			ErrorType  string `json:"error_type"`
			Difference string `json:"intentional_difference"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(data, &reference); err != nil {
		t.Fatal(err)
	}
	if reference.Schema != 1 || reference.DirectoryContacted == nil || *reference.DirectoryContacted || reference.Complete == nil || *reference.Complete || reference.Module == "" || reference.Assembly == "" || len(reference.Cases) != 41 {
		t.Fatal("invalid offline reference provenance/scope")
	}
	malformedNot := regexp.MustCompile(`\(!([^()]*)\)`)
	hexEscape := regexp.MustCompile(`\\[0-9A-Fa-f]{2}`)
	for _, test := range reference.Cases {
		t.Run(test.Expression, func(t *testing.T) {
			options := ADFilterOptions{Variables: make(map[string]any)}
			switch test.Profile {
			case "object":
			case "user":
				options.Profile = ADFilterUser
			case "computer":
				options.Profile = ADFilterComputer
			case "group":
				options.Profile = ADFilterGroup
			default:
				t.Fatal("unknown reference profile")
			}
			for name, value := range test.Variables {
				switch value.Kind {
				case "string":
					options.Variables[name] = value.Value
				case "time":
					v, e := time.Parse(time.RFC3339Nano, value.Value)
					if e != nil {
						t.Fatal(e)
					}
					options.Variables[name] = v
				case "sid":
					v, e := ParseSID(value.Value)
					if e != nil {
						t.Fatal(e)
					}
					options.Variables[name] = v
				default:
					t.Fatal("unknown reference variable kind")
				}
			}
			filter, err := ParseADFilter(test.Expression, options)
			if test.Difference != "" {
				if test.Difference != "reject_fractional_literal" && test.Difference != "reject_exponent_literal" {
					t.Fatal("unreviewed reference difference")
				}
				if !errors.Is(err, ErrADFilterConversion) {
					t.Fatalf("expected deliberate precision rejection: %v", err)
				}
				return
			}
			if test.ErrorType != "" {
				if err == nil {
					t.Fatal("reference rejects this expression")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, _ := filter.LDAP()
			// The local parser emits (!attribute=value) for negative comparison
			// rewrites. Parenthesize its child to obtain valid RFC 4515 grammar.
			want := malformedNot.ReplaceAllString(test.LDAP, `(!($1))`)
			want = hexEscape.ReplaceAllStringFunc(want, strings.ToLower)
			want = strings.ReplaceAll(want, `\2f`, "/")
			for strings.Contains(want, "**") {
				want = strings.ReplaceAll(want, "**", "*")
			}
			if got != want {
				t.Fatalf("SDK=%q normalized reference=%q raw reference=%q", got, want, test.LDAP)
			}
		})
	}
}
