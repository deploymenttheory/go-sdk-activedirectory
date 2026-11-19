// Command portablediscovery observes explicit-domain DNS candidates, then
// authenticates one explicitly selected controller through the public SDK.
// Supply credentials only through bounded private stdin or caller-owned files.
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
	"strings"
	"time"

	ad "github.com/deploymenttheory/go-sdk-activedirectory/activedirectory"
	"github.com/deploymenttheory/go-sdk-activedirectory/activedirectory/services/discovery"
)

var (
	buildRevision string
	validRunID    = regexp.MustCompile(`\A[A-Za-z0-9_.-]{1,64}\z`)
	validRevision = regexp.MustCompile(`\A[0-9a-f]{40}\z`)
)

type report struct {
	SchemaVersion    int                               `json:"schema_version"`
	SourceRevision   string                            `json:"source_revision"`
	SourceMatches    bool                              `json:"source_label_matches"`
	Platform         string                            `json:"platform"`
	Toolchain        string                            `json:"toolchain"`
	RunID            string                            `json:"run_id"`
	Success          bool                              `json:"success"`
	DNS              *discovery.DNSDiscoveryResult     `json:"dns,omitempty"`
	Identity         discovery.AuthenticatedController `json:"identity"`
	Projections      []projection                      `json:"projections"`
	ErrorClass       string                            `json:"error_class,omitempty"`
	IdentityMismatch bool                              `json:"identity_mismatch"`
	Ambiguous        bool                              `json:"ambiguous"`
	NoCandidates     bool                              `json:"no_candidates"`
	LDAPStatus       *uint32                           `json:"ldap_status,omitempty"`
	KerberosStatus   *int32                            `json:"kerberos_status,omitempty"`
}

type projection struct {
	Kind       string  `json:"kind"`
	Complete   bool    `json:"complete"`
	Value      any     `json:"result"`
	ErrorClass string  `json:"error_class,omitempty"`
	LDAPStatus *uint32 `json:"ldap_status,omitempty"`
}

func readRequest(reader io.Reader) (request, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 128*1024+1))
	defer clear(data)
	if err != nil || len(data) > 128*1024 || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return request{}, errors.New("one bounded discovery input object is required")
	}
	if err = uniqueFields(data); err != nil {
		return request{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input request
	if err = decoder.Decode(&input); err != nil {
		clear(input.Password)
		return request{}, errors.New("invalid discovery input")
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		clear(input.Password)
		return request{}, errors.New("exactly one discovery input object is required")
	}
	return input, nil
}

func uniqueFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid discovery input")
	}
	seen := map[string]bool{}
	for decoder.More() {
		name, err := decoder.Token()
		field, ok := name.(string)
		// encoding/json matches field names case-insensitively. Reject that
		// equivalent spelling too, rather than permitting a later override.
		field = strings.ToLower(field)
		if err != nil || !ok || seen[field] {
			return errors.New("duplicate or malformed discovery input field")
		}
		seen[field] = true
		var raw json.RawMessage
		err = decoder.Decode(&raw)
		clear(raw)
		if err != nil {
			return errors.New("invalid discovery input")
		}
	}
	return nil
}

func probe(ctx context.Context, input request) (result report, err error) {
	result = report{
		SchemaVersion:  1,
		SourceRevision: buildRevision,
		SourceMatches:  buildRevision != "" && buildRevision == input.SourceRevision,
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		Toolchain:      runtime.Version(),
	}
	var connection *ad.Client
	defer func() {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
		result.Success = err == nil
		if err != nil {
			result.ErrorClass = ad.Classify(err).String()
		}
		result.IdentityMismatch = errors.Is(err, discovery.ErrDiscoveryIdentity)
		result.Ambiguous = errors.Is(err, discovery.ErrDiscoveryAmbiguous)
		result.NoCandidates = errors.Is(err, discovery.ErrDiscoveryNoCandidates)
		var ldapError *ad.LDAPError
		if errors.As(err, &ldapError) {
			code := ldapError.Code
			result.LDAPStatus = &code
		}
		var kerberosError *ad.KerberosError
		if errors.As(err, &kerberosError) && kerberosError.Code != 0 {
			code := kerberosError.Code
			result.KerberosStatus = &code
		}
	}()
	if input.RunID != "" && !validRunID.MatchString(input.RunID) || input.SourceRevision != "" && (!validRevision.MatchString(input.SourceRevision) || !result.SourceMatches) {
		return result, errors.New("invalid or mismatched public source metadata")
	}
	result.RunID = input.RunID
	config, selection, err := requestConfig(input)
	if err != nil {
		return result, err
	}
	kinds := input.Projections
	if len(kinds) == 0 {
		kinds = []string{"domain", "forest", "controller", "controllers"}
	}
	seen := map[string]bool{}
	for _, kind := range kinds {
		if kind != "domain" && kind != "forest" && kind != "controller" && kind != "controllers" || seen[kind] {
			return result, errors.New("projections must be unique supported topology names")
		}
		seen[kind] = true
	}
	if input.LookupDNS {
		observed, lookupErr := discovery.LookupDomainControllers(
			ctx,
			discovery.DNSDiscoveryOptions{DomainDNS: input.DomainDNS, SiteName: input.SiteName, Timeout: 30 * time.Second},
		)
		result.DNS = &observed
		if lookupErr != nil {
			return result, lookupErr
		}
		candidate, selectErr := observed.Select(ad.Endpoint{Host: config.Endpoint.Host, Port: input.DNSPort})
		if selectErr != nil {
			return result, selectErr
		}
		selection.Candidate = &candidate
	}
	connection, result.Identity, err = ad.DialDomainController(ctx, config, selection)
	if err != nil {
		return result, err
	}
	for _, kind := range kinds {
		observed, readErr := readProjection(ctx, connection, kind)
		result.Projections = append(result.Projections, observed)
		err = errors.Join(err, readErr)
	}
	return result, err
}

func readProjection(ctx context.Context, connection *ad.Client, kind string) (result projection, err error) {
	result.Kind = kind
	switch kind {
	case "domain":
		value, e := connection.Discovery.Domain(ctx, discovery.DomainOptions{})
		result.Value, result.Complete, err = value, value.Observation.Complete, e
	case "forest":
		value, e := connection.Discovery.Forest(ctx)
		result.Value, result.Complete, err = value, value.Observation.Complete, e
	case "controller":
		value, e := connection.Discovery.DomainController(ctx, discovery.DomainControllerOptions{})
		result.Value, result.Complete, err = value, value.Observation.Complete, e
	case "controllers":
		value, e := connection.Discovery.DomainControllers(ctx, discovery.DomainControllersQuery{})
		result.Value, result.Complete, err = value, value.Observation.Complete, e
	}
	if !result.Complete && err == nil {
		err = ad.ErrIncompleteResult
	}
	if err != nil {
		result.ErrorClass = ad.Classify(err).String()
	}
	var status *ad.LDAPError
	if errors.As(err, &status) {
		value := status.Code
		result.LDAPStatus = &value
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
			return errors.New("cannot create fresh discovery report")
		}
		defer func() {
			if closeErr := output.Close(); closeErr != nil {
				err = errors.Join(err, errors.New("cannot finalize discovery report"))
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, probeErr := probe(ctx, input)
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return errors.New("cannot encode public discovery report")
	}
	encoded = append(encoded, '\n')
	if output != nil {
		if _, err = output.Write(encoded); err != nil {
			return errors.New("cannot write discovery report")
		}
	}
	if _, err = writer.Write(encoded); err != nil {
		return errors.New("cannot write public discovery output")
	}
	if probeErr != nil {
		return errors.New("discovery observation incomplete; inspect the structured report")
	}
	return nil
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
