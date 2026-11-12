package coverage

import (
	"crypto/sha256"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

// ImportReference extracts a new snapshot from an explicitly selected local
// checkout/download of Microsoft's Markdown. It does not access the network or
// expand the approved command inventory implicitly.
func ImportReference(directory, commit string, names []string) (Reference, error) {
	r := Reference{
		SchemaVersion: 1,
		Repository:    "https://github.com/MicrosoftDocs/windows-powershell-docs",
		Commit:        commit,
		View:          "windowsserver2025-ps",
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(commit) || len(names) == 0 ||
		!unique(names) {
		return r, invalidf("a full commit and unique approved names are required")
	}
	fs, err := os.OpenRoot(directory)
	if err != nil {
		return r, fmt.Errorf("open documentation directory: %w", err)
	}
	defer fs.Close()
	names = slices.Clone(names)
	slices.Sort(names)
	for _, name := range names {
		if !regexp.MustCompile(`^[A-Za-z]+-AD[A-Za-z]+$`).MatchString(name) {
			return r, invalidf("invalid command name %q", name)
		}
		raw, err := fs.ReadFile(name + ".md")
		if err != nil {
			return r, fmt.Errorf("read %s: %w", name, err)
		}
		text := strings.ReplaceAll(strings.TrimPrefix(string(raw), "\ufeff"), "\r\n", "\n")
		section := regexp.MustCompile(`(?ms)^## SYNTAX\s*\n(.*?)(?:^## |\z)`).
			FindStringSubmatch(text)
		if section == nil {
			return r, invalidf("%s: missing SYNTAX section", name)
		}
		command := Command{
			Name:   name,
			Source: r.Repository + "/blob/" + commit + "/docset/winserver2025-ps/ActiveDirectory/" + name + ".md",
			SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)),
		}
		parameters := map[string]bool{}
		for _, section := range regexp.MustCompile(`(?m)^### `).Split(section[1], -1) {
			blocks := regexp.MustCompile("(?s)```[^\\n]*\\n(.*?)```").
				FindAllStringSubmatch(section, -1)
			if len(blocks) == 0 {
				continue
			}
			heading := strings.TrimSpace(strings.SplitN(section, "\n", 2)[0])
			if heading == "" || strings.HasPrefix(heading, "```") {
				heading = "Default"
			}
			set := ParameterSet{Name: heading, Parameters: []string{}}
			setParameters := map[string]bool{}
			for _, block := range blocks {
				for _, match := range regexp.MustCompile(`(?:^|[^A-Za-z0-9])-([A-Za-z][A-Za-z0-9]+)\b`).FindAllStringSubmatch(block[1], -1) {
					setParameters[match[1]] = true
					parameters[match[1]] = true
				}
			}
			for p := range setParameters {
				set.Parameters = append(set.Parameters, p)
			}
			slices.Sort(set.Parameters)
			command.ParameterSets = append(command.ParameterSets, set)
		}
		if len(command.ParameterSets) == 0 {
			return r, invalidf("%s: no syntax blocks", name)
		}
		for _, match := range regexp.MustCompile(`(?m)^### -([A-Za-z][A-Za-z0-9]+)\s*$`).FindAllStringSubmatch(text, -1) {
			parameters[match[1]] = true
		}
		for p := range parameters {
			command.Parameters = append(command.Parameters, p)
		}
		slices.Sort(command.Parameters)
		r.Commands = append(r.Commands, command)
	}
	return r, nil
}
