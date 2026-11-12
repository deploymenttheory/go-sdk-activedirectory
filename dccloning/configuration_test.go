package dccloning

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func staticConfig() CloneConfiguration {
	return CloneConfiguration{ComputerName: "CLONE-2", Static: true, IPv4Address: "192.0.2.20", IPv4SubnetMask: "255.255.255.0", IPv4DNSResolvers: []string{"192.0.2.10"}}
}

func TestCloneConfigurationValidation(t *testing.T) {
	for _, c := range []CloneConfiguration{{}, {ComputerName: " clone-1 ", SiteName: " Zürich & East "}, {IPv4DNSResolvers: []string{" 192.0.2.1 ", "192.0.2.1"}}, {Static: true, IPv6DNSResolvers: []string{"2001:db8::1"}}, staticConfig()} {
		if err := c.Validate(); err != nil {
			t.Fatalf("valid %#v: %v", c, err)
		}
	}
	cases := map[string]CloneConfiguration{
		"numeric name": {ComputerName: "123"}, "long name": {ComputerName: "abcdefghijklmnop"}, "dotted name": {ComputerName: "clone.test"}, "hyphen name": {ComputerName: "-clone"}, "unicode name": {ComputerName: "clöné"},
		"invalid UTF8": {SiteName: string([]byte{0xff})}, "invalid XML": {SiteName: "east\uffff"}, "control": {SiteName: "east\x00"}, "long UTF16": {SiteName: strings.Repeat("🛰", 128)},
		"too many DNS": {IPv4DNSResolvers: []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"}}, "blank DNS": {IPv4DNSResolvers: []string{" "}}, "wrong family": {IPv4DNSResolvers: []string{"2001:db8::1"}}, "mapped IPv6": {IPv6DNSResolvers: []string{"::ffff:192.0.2.1"}}, "scoped IPv6": {IPv6DNSResolvers: []string{"fe80::1%1"}}, "multicast DNS": {IPv4DNSResolvers: []string{"224.0.0.1"}}, "unspecified DNS": {IPv6DNSResolvers: []string{"::"}},
		"static empty": {Static: true}, "static IPv4 DNS only": {Static: true, IPv4DNSResolvers: []string{"192.0.2.1"}}, "dynamic address": {IPv4Address: "192.0.2.2"},
	}
	c := staticConfig()
	c.IPv4SubnetMask = "255.0.255.0"
	cases["noncontiguous mask"] = c
	c = staticConfig()
	c.IPv4DefaultGateway = "::1"
	cases["wrong gateway family"] = c
	c = staticConfig()
	c.IPv4DNSResolvers = nil
	cases["static missing DNS"] = c
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := c.Validate(); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestCloneConfigurationXMLContract(t *testing.T) {
	c := staticConfig()
	c.SiteName = " East & <West> "
	c.IPv4DefaultGateway = "192.0.2.1"
	c.IPv4DNSResolvers = []string{"192.0.2.10", "192.0.2.11"}
	c.IPv6DNSResolvers = []string{"2001:db8::10"}
	data, err := EncodeCloneConfiguration(c)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var names []string
	var sites []string
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if start, ok := token.(xml.StartElement); ok {
			names = append(names, start.Name.Local)
			if len(names) == 1 {
				if start.Name.Space != configNamespace {
					t.Fatalf("root namespace %q", start.Name.Space)
				}
			} else if start.Name.Space != "" {
				t.Fatalf("qualified descendant: %#v", start.Name)
			}
			if start.Name.Local == "SiteName" {
				var text string
				if err := decoder.DecodeElement(&text, &start); err != nil {
					t.Fatal(err)
				}
				sites = append(sites, text)
			}
		}
	}
	want := []string{"DCCloneConfig", "ComputerName", "SiteName", "IPSettings", "IPv4Settings", "StaticSettings", "Address", "SubnetMask", "DefaultGateway", "DNSResolver", "DNSResolver", "IPv6Settings", "StaticSettings", "DNSResolver"}
	if !reflect.DeepEqual(names, want) || !reflect.DeepEqual(sites, []string{"East & <West>"}) {
		t.Fatalf("names %v / sites %v", names, sites)
	}
	if !bytes.HasPrefix(data, []byte("<?xml version=\"1.0\" encoding=\"utf-8\"?>")) {
		t.Fatalf("encoding: %q", data)
	}
	empty, err := EncodeCloneConfiguration(CloneConfiguration{})
	if err != nil || bytes.Contains(empty, []byte("IPSettings")) {
		t.Fatalf("empty: %s / %v", empty, err)
	}
	dynamic, err := EncodeCloneConfiguration(CloneConfiguration{IPv6DNSResolvers: []string{"2001:db8::1", "2001:db8::1"}})
	if err != nil || !bytes.Contains(dynamic, []byte("DynamicSettings")) || bytes.Count(dynamic, []byte("<DNSResolver>")) != 2 {
		t.Fatalf("dynamic: %s / %v", dynamic, err)
	}
}

type fakeConfigEnvironment struct {
	directories  []string
	observations ConfigPrerequisites
	err          error
	calls        int
}

func (e *fakeConfigEnvironment) prerequisites(context.Context) (ConfigPrerequisites, error) {
	e.calls++
	return e.observations, e.err
}
func (e *fakeConfigEnvironment) configDirectories(context.Context) ([]string, error) {
	e.calls++
	return e.directories, nil
}
func (e *fakeConfigEnvironment) equal(a, b string) (bool, error) { return a == b, nil }

func configPublisher(t *testing.T, overwriteWant bool) publishFile {
	t.Helper()
	return func(temporary, destination string, overwrite bool) error {
		if overwrite != overwriteWant {
			t.Fatalf("overwrite = %v", overwrite)
		}
		// A portable test publication seam; production Windows uses MoveFileExW.
		if overwrite {
			if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		return os.Rename(temporary, destination)
	}
}

func TestGenerateConfigOfflineSkipsChecksAndReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ConfigFileName)
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := generateConfiguration(context.Background(), ConfigOptions{Offline: true, Directory: dir}, nil, configPublisher(t, true))
	if err != nil || r.Outcome != Written || !r.ChecksSkipped || r.Prerequisites.Complete || r.Path != path {
		t.Fatalf("%#v / %v", r, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte("DCCloneConfig")) {
		t.Fatalf("%s / %v", data, err)
	}
}

func TestGenerateConfigOnlineLocationsAndFailures(t *testing.T) {
	for _, scenario := range []string{"default", "explicit", "other location collision", "target collision", "unsupported path", "prerequisite failure", "incomplete prerequisite", "cancelled", "uncertain"} {
		t.Run(scenario, func(t *testing.T) {
			dir, second := t.TempDir(), t.TempDir()
			e := &fakeConfigEnvironment{directories: []string{dir, second}, observations: ConfigPrerequisites{Complete: true}}
			options := ConfigOptions{}
			want := error(nil)
			outcome := NotWritten
			calls := 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sentinel := errors.New("native publication failed")
			switch scenario {
			case "default":
				outcome = Written
			case "explicit":
				options.Directory = second
				outcome = Written
			case "other location collision":
				want = ErrOutputExists
				if err := os.WriteFile(filepath.Join(second, ConfigFileName), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "target collision":
				want = ErrOutputExists
				if err := os.WriteFile(filepath.Join(dir, ConfigFileName), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsupported path":
				options.Directory = t.TempDir()
				want = ErrInvalidPath
			case "prerequisite failure":
				e.err = sentinel
				want = sentinel
			case "incomplete prerequisite":
				e.observations.Complete = false
				want = ErrClonePrerequisite
			case "cancelled":
				cancel()
				want = context.Canceled
			case "uncertain":
				want = sentinel
				outcome = WriteUncertain
			}
			publisher := func(temporary, destination string, overwrite bool) error {
				calls++
				if scenario == "uncertain" {
					return sentinel
				}
				return configPublisher(t, false)(temporary, destination, overwrite)
			}
			r, err := generateConfiguration(ctx, options, e, publisher)
			if !errors.Is(err, want) || r.Outcome != outcome || r.ChecksSkipped {
				t.Fatalf("%#v / %v; want %v/%s", r, err, want, outcome)
			}
			if outcome == NotWritten && calls != 0 || outcome != NotWritten && calls != 1 {
				t.Fatalf("publication calls %d", calls)
			}
			if scenario == "default" && r.Path != filepath.Join(dir, ConfigFileName) || scenario == "explicit" && r.Path != filepath.Join(second, ConfigFileName) {
				t.Fatalf("destination %s", r.Path)
			}
			for _, directory := range []string{dir, second} {
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if entry.Name() != ConfigFileName {
						t.Fatalf("leaked temporary file: %s", entry.Name())
					}
					if outcome == NotWritten {
						data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
						if err != nil || string(data) != "preserve" {
							t.Fatalf("changed preexisting output: %q/%v", data, err)
						}
					}
				}
			}
		})
	}
}

func TestGenerateConfigRejectsInputBeforeNativeCalls(t *testing.T) {
	for _, options := range []ConfigOptions{{Timeout: -time.Second}, {Offline: true}, {Directory: "bad\x00path"}, {Configuration: CloneConfiguration{IPv4DNSResolvers: []string{"192.0.2.1"}, IPv6DNSResolvers: []string{"2001:db8::1"}}}} {
		r, err := GenerateConfig(context.Background(), options)
		if err == nil || r.Outcome != NotWritten {
			t.Fatalf("%#v: %#v / %v", options, r, err)
		}
	}
}
