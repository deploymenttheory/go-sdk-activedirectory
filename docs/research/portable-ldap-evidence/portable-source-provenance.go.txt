// Command portable-source-provenance records actual build inputs and proves
// runtime source identity against a separately named SDK baseline commit.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type record struct {
	SchemaVersion        int               `json:"schema_version"`
	SourceRevision       string            `json:"source_revision"`
	SDKBaseRevision      string            `json:"sdk_base_revision"`
	GoVersion            string            `json:"go_version"`
	RuntimeByteIdentical bool              `json:"runtime_byte_identical"`
	RuntimeFiles         map[string]string `json:"runtime_files_sha256"`
	BuildInputs          map[string]string `json:"actual_build_inputs_sha256"`
}

func git(repo string, args ...string) ([]byte, error) {
	prefix := []string{"-c", "safe.directory=" + repo, "-C", repo}
	out, err := exec.Command("git", append(prefix, args...)...).Output()
	if err != nil {
		return nil, errors.New("git provenance query failed")
	}
	return out, nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func runtimeFile(name string) bool {
	return name == "go.mod" || name == "go.sum" ||
		strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") &&
			(strings.HasPrefix(name, "activedirectory/") || strings.HasPrefix(name, "conditions/") || strings.HasPrefix(name, "dccloning/") || strings.HasPrefix(name, "3rd_party/"))
}

func run(repo, base, out string) error {
	repo, err := filepath.Abs(repo)
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(base) {
		return errors.New("baseline must be an immutable commit")
	}
	for _, args := range [][]string{{"diff", "--quiet"}, {"diff", "--cached", "--quiet"}} {
		if _, err := git(repo, args...); err != nil {
			return errors.New("build source must have no tracked changes")
		}
	}
	untracked, err := git(repo, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return err
	}
	if len(untracked) != 0 {
		return errors.New("build source must have no untracked inputs")
	}
	revision, err := git(repo, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	current, err := git(repo, "ls-files", "-z")
	if err != nil {
		return err
	}
	previous, err := git(repo, "ls-tree", "-rz", "--name-only", base)
	if err != nil {
		return err
	}
	expected := map[string]bool{}
	for _, entry := range bytes.Split(previous, []byte{0}) {
		name := string(entry)
		if runtimeFile(name) {
			expected[name] = true
		}
	}
	result := record{
		SchemaVersion:   1,
		SourceRevision:  strings.TrimSpace(string(revision)),
		SDKBaseRevision: base,
		GoVersion:       runtime.Version(),
		RuntimeFiles:    map[string]string{},
		BuildInputs:     map[string]string{},
	}
	for _, entry := range bytes.Split(current, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		name := string(entry)
		actual, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(name)))
		if err != nil {
			return err
		}
		result.BuildInputs[name] = digest(actual)
		if !runtimeFile(name) {
			continue
		}
		if !expected[name] {
			return fmt.Errorf("runtime source added relative to baseline: %s", name)
		}
		canonical, err := git(repo, "show", base+":"+name)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, canonical) {
			return fmt.Errorf("runtime source differs from baseline bytes: %s", name)
		}
		result.RuntimeFiles[name] = digest(actual)
		delete(expected, name)
	}
	if len(expected) != 0 {
		return errors.New("runtime source removed relative to baseline")
	}
	result.RuntimeByteIdentical = true
	file, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(result)
	return errors.Join(writeErr, file.Close())
}

func main() {
	repo := flag.String("repo", ".", "clean repository containing actual build inputs")
	base := flag.String("sdk-base", "", "immutable SDK runtime baseline")
	out := flag.String("out", "", "fresh public provenance file")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "fresh output path required")
		os.Exit(2)
	}
	if err := run(*repo, *base, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
