// Command portablereplication reads replication diagnostics with explicit secure
// authentication. Supply one bounded JSON object on private redirected stdin;
// no credential argument, ambient cache, directory write or helper is used.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/replication"
)

var (
	buildRevision string
	validRunID    = regexp.MustCompile(`\A[A-Za-z0-9_.-]{1,64}\z`)
	validRevision = regexp.MustCompile(`\A[0-9a-f]{40}\z`)
)

type request struct {
	Endpoint       string                                              `json:"endpoint"`
	Backend        string                                              `json:"backend"`
	Transport      string                                              `json:"transport"`
	Source         string                                              `json:"source"`
	Username       string                                              `json:"username"`
	Realm          string                                              `json:"realm"`
	Domain         string                                              `json:"domain,omitempty"`
	LDAPSPN        string                                              `json:"ldap_spn"`
	Password       []byte                                              `json:"password_base64,omitempty"`
	KeytabPath     string                                              `json:"keytab_path,omitempty"`
	CachePath      string                                              `json:"cache_path,omitempty"`
	CAFile         string                                              `json:"ca_file,omitempty"`
	Kind           string                                              `json:"kind"`
	Scope          string                                              `json:"scope"`
	Servers        []ad.Endpoint                                       `json:"servers,omitempty"`
	DomainDNS      string                                              `json:"domain_dns,omitempty"`
	ForestDNS      string                                              `json:"forest_dns,omitempty"`
	SiteName       string                                              `json:"site_name,omitempty"`
	Principals     map[string]replication.ReplicationServicePrincipals `json:"service_principals,omitempty"`
	PartitionDN    string                                              `json:"partition_dn,omitempty"`
	RunID          string                                              `json:"run_id,omitempty"`
	SourceRevision string                                              `json:"source_revision,omitempty"`
	Result         string                                              `json:"result,omitempty"`
}

type report struct {
	SchemaVersion    int           `json:"schema_version"`
	SourceRevision   string        `json:"source_revision"`
	SourceVerified   bool          `json:"source_label_matches"`
	RunID            string        `json:"run_id"`
	Platform         string        `json:"platform"`
	Toolchain        string        `json:"toolchain"`
	Backend          string        `json:"backend,omitempty"`
	CredentialSource string        `json:"credential_source,omitempty"`
	Transport        string        `json:"transport,omitempty"`
	Success          bool          `json:"success"`
	Queries          []queryReport `json:"queries"`
	ErrorClass       string        `json:"error_class,omitempty"`
}

type queryReport struct {
	Kind       string   `json:"kind"`
	Complete   bool     `json:"complete"`
	Value      any      `json:"result"`
	ErrorClass string   `json:"error_class,omitempty"`
	Statuses   []status `json:"statuses,omitempty"`
}

func readRequest(reader io.Reader) (request, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 128*1024+1))
	defer clear(data)
	if err != nil {
		return request{}, errors.New("unable to read replication input")
	}
	if len(data) > 128*1024 || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return request{}, errors.New("one bounded replication input object is required")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input request
	if err = decoder.Decode(&input); err != nil {
		clear(input.Password)
		return request{}, errors.New("invalid replication input")
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		clear(input.Password)
		return request{}, errors.New("exactly one replication input object is required")
	}
	return input, nil
}

func probe(ctx context.Context, input request) (result report, err error) {
	result = report{
		SchemaVersion: 1, SourceRevision: buildRevision, SourceVerified: buildRevision != "" && buildRevision == input.SourceRevision,
		Platform: runtime.GOOS + "/" + runtime.GOARCH, Toolchain: runtime.Version(),
	}
	defer func() {
		result.Success = err == nil
		if err != nil {
			result.ErrorClass = ad.Classify(err).String()
		}
	}()
	if input.RunID != "" && !validRunID.MatchString(input.RunID) || input.SourceRevision != "" && (!validRevision.MatchString(input.SourceRevision) || !result.SourceVerified) {
		return result, errors.New("invalid or mismatched public source metadata")
	}
	result.RunID = input.RunID
	config, selection, err := requestConfig(input)
	if err != nil {
		return result, err
	}
	result.Backend, result.CredentialSource, result.Transport = input.Backend, input.Source, input.Transport
	kinds := []string{input.Kind}
	if input.Kind == "all" {
		kinds = []string{"partners", "failures", "queue"}
	}
	for _, kind := range kinds {
		var value any
		var complete bool
		var queryErr error
		switch kind {
		case "partners":
			observed, e := replication.ReadReplicationPartners(
				ctx,
				config,
				replication.ReplicationPartnerQuery{Selection: selection, Direction: replication.ReplicationBoth, PartitionDN: input.PartitionDN},
			)
			value, complete, queryErr = observed, observed.Complete, e
		case "failures":
			observed, e := replication.ReadReplicationFailures(ctx, config, replication.ReplicationFailureQuery{Selection: selection})
			value, complete, queryErr = observed, observed.Complete, e
		case "queue":
			observed, e := replication.ReadReplicationQueue(ctx, config, replication.ReplicationQueueQuery{Selection: selection})
			value, complete, queryErr = observed, observed.Complete, e
		}
		if !complete && queryErr == nil {
			queryErr = ad.ErrIncompleteResult
		}
		query := queryReport{Kind: kind, Complete: complete, Value: value, Statuses: statuses(queryErr)}
		if queryErr != nil {
			query.ErrorClass = ad.Classify(queryErr).String()
		}
		result.Queries = append(result.Queries, query)
		err = errors.Join(err, queryErr)
	}
	return result, err
}

func run(reader io.Reader, writer io.Writer) (err error) {
	input, err := readRequest(reader)
	if err != nil {
		return err
	}
	defer clear(input.Password)
	var output *os.File
	if input.Result != "" {
		output, err = os.OpenFile(input.Result, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return errors.New("cannot create fresh replication report")
		}
		defer func() {
			if closeErr := output.Close(); closeErr != nil {
				err = errors.Join(err, errors.New("cannot finalize replication report"))
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, probeErr := probe(ctx, input)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if output != nil {
		if _, err = output.Write(encoded); err != nil {
			return errors.New("cannot write replication report")
		}
	}
	if _, err = writer.Write(encoded); err != nil {
		return fmt.Errorf("write public replication report: %w", err)
	}
	if probeErr != nil {
		return errors.New("replication observation incomplete; inspect the structured report")
	}
	return nil
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
