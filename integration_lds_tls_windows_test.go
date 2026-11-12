//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestADLDSTLSFixtureRejectsMalformedInputWithoutDisclosure(t *testing.T) {
	const secret = "synthetic-tls-peer-fixture-secret"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	for _, payload := range []string{
		`{"Password":"` + encoded + `","` + secret + `":true}`,
		`{"Password":"` + encoded + `"} {"extra":"` + secret + `"}`,
		`{"Server":"outside.invalid","Password":"` + encoded + `"}`,
		`{"Server":"dc2.ad.sdk.test","Transport":"ldap","Password":"` + encoded + `"}`,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		resultPath := filepath.Join(t.TempDir(), "result.json")
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestADLDSTLSLab$")
		command.Env = append(
			os.Environ(),
			"ADSDK_LDS_TLS_LAB=1",
			"ADSDK_LDS_TLS_RESULT="+resultPath,
		)
		command.Stdin = strings.NewReader(payload)
		output, err := command.CombinedOutput()
		cancel()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
			!bytes.Contains(output, []byte("FAIL")) {
			t.Fatal("malformed TLS fixture was not rejected by the isolated test process")
		}
		if bytes.Contains(output, []byte(secret)) || bytes.Contains(output, []byte(encoded)) {
			t.Fatal("TLS fixture rejection disclosed synthetic credential material")
		}
		if _, err := os.Stat(resultPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("rejected TLS fixture created a success artifact")
		}
	}
}

// One case per process lets the owner pair this observation with one tls-peer
// connection artifact. Only the peer can establish selected-certificate and
// zero-BindRequest evidence; a failed Dial alone does not prove either.
func TestADLDSTLSLab(t *testing.T) {
	if os.Getenv("ADSDK_LDS_TLS_LAB") != "1" {
		t.Skip("requires the isolated TLS peer and redirected fixture input")
	}
	var input struct {
		Server, Transport, Partition, BindDN, Marker string
		Port                                         uint16
		Password                                     []byte
		ExpectFailure                                bool
	}
	// The mutable decoded password may be allocated before a later parse error.
	defer func() { clear(input.Password) }()
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
	defer clear(payload)
	if err != nil || len(payload) > 16384 {
		t.Fatal("invalid TLS fixture input")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		t.Fatal("invalid TLS fixture encoding")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		t.Fatal("TLS fixture must contain exactly one JSON object")
	}
	if !validServerHost(input.Server) || !strings.HasSuffix(strings.ToLower(input.Server), ".ad.sdk.test") ||
		!strings.HasPrefix(input.Marker, "ad-sdk-lds:") || input.Partition == "" || input.BindDN == "" ||
		input.Port == 0 ||
		len(input.Password) == 0 {
		t.Fatal("incomplete fixture or outside isolated TLS namespace")
	}
	var transport Transport
	switch input.Transport {
	case "ldaps":
		transport = TransportLDAPS
	case "starttls":
		transport = TransportStartTLS
	default:
		t.Fatal("TLS fixture transport must be ldaps or starttls")
	}
	config := Config{
		Endpoint:       Endpoint{Host: input.Server, Port: input.Port},
		Transport:      transport,
		Authentication: AuthenticationSimple,
		Partition:      input.Partition,
		Credentials: &Credentials{
			Username: input.BindDN,
			Password: input.Password,
		},
		Timeout: 10 * time.Second,
	}
	if err := config.Validate(); err != nil {
		t.Fatal("invalid TLS fixture configuration")
	}
	path := os.Getenv("ADSDK_LDS_TLS_RESULT")
	if path == "" {
		t.Fatal("missing nonsecret TLS result destination")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("TLS result destination must be new")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client, dialErr := Dial(ctx, config)
	result := tlsLabResult{
		Server:        input.Server,
		Port:          input.Port,
		Transport:     input.Transport,
		ExpectFailure: input.ExpectFailure,
		DialSucceeded: dialErr == nil &&
			client != nil,
		TLSNegotiationError: errors.Is(dialErr, ErrTLSNegotiation),
		NativeErrors:        tlsLabNativeErrors(dialErr),
	}
	if input.ExpectFailure {
		result.Passed = client == nil && dialErr != nil && result.TLSNegotiationError &&
			context.Cause(ctx) == nil
		if client != nil {
			closeErr := client.Close()
			result.NativeErrors = append(result.NativeErrors, tlsLabNativeErrors(closeErr)...)
		}
	} else if result.DialSucceeded {
		partition, readErr := client.Partition(ctx)
		closeErr := client.Close()
		result.NativeErrors = append(
			result.NativeErrors,
			tlsLabNativeErrors(errors.Join(readErr, closeErr))...)
		result.PartitionRead = readErr == nil && partition.DistinguishedName != "" &&
			partition.InstanceType&1 != 0
		result.Passed = result.PartitionRead && closeErr == nil
		if result.PartitionRead {
			result.Partition = partition.DistinguishedName
			result.InstanceType = partition.InstanceType
		}
	}
	result.ContextExpired = context.Cause(ctx) != nil
	if result.ContextExpired {
		result.Passed = false
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal("cannot encode TLS observation")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal("cannot create TLS result")
	}
	_, writeErr := file.Write(append(data, '\n'))
	closeErr := file.Close()
	if errors.Join(writeErr, closeErr) != nil {
		t.Fatal("cannot write TLS result")
	}
	if !result.Passed {
		t.Fatal("TLS case did not satisfy its expected result; inspect the nonsecret observation")
	}
}

type tlsLabResult struct {
	Passed              bool                `json:"passed"`
	Server              string              `json:"server"`
	Port                uint16              `json:"port"`
	Transport           string              `json:"transport"`
	ExpectFailure       bool                `json:"expect_failure"`
	DialSucceeded       bool                `json:"dial_succeeded"`
	TLSNegotiationError bool                `json:"tls_negotiation_error"`
	ContextExpired      bool                `json:"context_expired"`
	PartitionRead       bool                `json:"partition_read"`
	Partition           string              `json:"partition,omitempty"`
	InstanceType        uint32              `json:"instance_type,omitempty"`
	NativeErrors        []tlsLabNativeError `json:"native_errors"`
}

type tlsLabNativeError struct {
	Kind string `json:"kind"`
	Code uint32 `json:"code"`
}

// Preserve every numeric LDAP/Win32 error in a joined chain. Do not include
// Error strings, diagnostic messages, matched DNs, or credential input.
func tlsLabNativeErrors(err error) []tlsLabNativeError {
	result := []tlsLabNativeError{}
	var visit func(error)
	visit = func(err error) {
		switch value := err.(type) {
		case *LDAPError:
			result = append(result, tlsLabNativeError{Kind: "ldap", Code: value.Code})
		case syscall.Errno:
			result = append(result, tlsLabNativeError{Kind: "win32", Code: uint32(value)})
		}
		switch value := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range value.Unwrap() {
				visit(child)
			}
		case interface{ Unwrap() error }:
			visit(value.Unwrap())
		}
	}
	visit(err)
	return result
}

func TestADLDSTLSNativeErrorEvidenceOmitsDiagnostics(t *testing.T) {
	const secret = "synthetic-native-diagnostic-secret"
	err := errors.Join(ErrTLSNegotiation,
		&LDAPError{Code: 81, Operation: secret, Diagnostic: secret, MatchedDN: secret},
		errors.Join(syscall.Errno(0x80090322), &LDAPError{Code: 82}))
	data, encodeErr := json.Marshal(tlsLabNativeErrors(err))
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	want := `[{"kind":"ldap","code":81},{"kind":"win32","code":2148074274},{"kind":"ldap","code":82}]`
	if string(data) != want || bytes.Contains(data, []byte(secret)) {
		t.Fatal("native error evidence lost codes or included diagnostic text")
	}
}
