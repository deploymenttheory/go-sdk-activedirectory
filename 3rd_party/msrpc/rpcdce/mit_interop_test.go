package rpcdce

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	krbclient "github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/client"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/keytab"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/messages"
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/gokrb5/v8/types"
)

// This independent implementation fixture is opt-in and offline. Python/MIT is
// only the test peer; the SDK runtime never launches a helper or native gateway.
func TestQualificationMITDCEOfflineInterop(t *testing.T) {
	for _, profile := range []int32{17, 18} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) { qualificationMITDCEOfflineInterop(t, profile) })
	}
}

func qualificationMITDCEOfflineInterop(t *testing.T, profile int32) {
	if runtime.GOOS != "linux" || os.Getenv("ADSDK_RPC_MIT_INTEROP") != "1" {
		t.Skip("explicit offline Linux MIT interoperability fixture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	dir := t.TempDir()
	kt := keytab.New()
	now := time.Now().UTC()
	if err := kt.AddEntry("ldap/dc.example.test", "EXAMPLE.TEST", "PUBLIC synthetic fixture only", now, 1, profile); err != nil {
		t.Fatal(err)
	}
	encoded, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	keytabPath := filepath.Join(dir, "synthetic.keytab")
	if err := os.WriteFile(keytabPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	configPath := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(
		configPath,
		[]byte("[libdefaults]\n default_realm = EXAMPLE.TEST\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n dns_canonicalize_hostname = false\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	service := types.NewPrincipalName(2, "ldap/dc.example.test")
	name := types.NewPrincipalName(1, "client")
	ticket, key, err := messages.NewTicket(
		name,
		"EXAMPLE.TEST",
		service,
		"EXAMPLE.TEST",
		types.NewKrbFlags(),
		kt,
		profile,
		1,
		now.Add(-time.Minute),
		now.Add(-time.Minute),
		now.Add(time.Hour),
		now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.KeyValue)
	actor, err := NewClient(
		ctx,
		"EXAMPLE.TEST",
		service,
		"EXAMPLE.TEST",
		name,
		krbclient.ServiceTicket{Ticket: ticket, Key: key, StartTime: now.Add(-time.Minute), EndTime: now.Add(time.Hour)},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer actor.Destroy()
	command := exec.CommandContext(ctx, "python3", "testdata/mit_dce_peer.py", keytabPath, "ldap/dc.example.test@EXAMPLE.TEST")
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C", "KRB5_CONFIG=" + configPath, "KRB5RCACHEDIR=" + dir}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close(); _ = command.Wait() }()
	encoder, decoder := json.NewEncoder(input), json.NewDecoder(bufio.NewReaderSize(output, 128*1024))
	var response struct {
		Major        uint32
		Flags        uint32
		Token, Body  []byte
		Confidential bool
	}
	exchange := func(request any) {
		t.Helper()
		if err := encoder.Encode(request); err != nil {
			t.Fatalf("MIT fixture input: %v", err)
		}
		response = struct {
			Major        uint32
			Flags        uint32
			Token, Body  []byte
			Confidential bool
		}{}
		if err := decoder.Decode(&response); err != nil {
			_ = command.Wait()
			t.Fatalf("MIT fixture output: %v; safe diagnostic=%s", err, diagnostic.String())
		}
	}
	first, err := actor.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exchange(struct {
		Op    string `json:"op"`
		Token []byte `json:"token"`
	}{"accept", first})
	if response.Major != 1 {
		t.Fatalf("MIT did not request DCE final leg: major%d", response.Major)
	}
	third, records, err := actor.Accept(ctx, response.Token)
	if err != nil {
		t.Fatal(err)
	}
	defer records.Destroy()
	exchange(struct {
		Op    string `json:"op"`
		Token []byte `json:"token"`
	}{"accept", third})
	if response.Major != 0 {
		t.Fatal("MIT did not accept DCE third leg")
	}
	if response.Flags&0x3e != 0x3e || response.Flags&1 != 0 {
		t.Fatalf("MIT completed without required nondelegated mutual/replay/sequence/privacy/integrity facts: flags%x", response.Flags)
	}
	header := make([]byte, 24)
	header[0], header[2], header[3], header[4] = 5, 0, 3, 0x10
	binary.LittleEndian.PutUint32(header[12:], 1)
	trailer := []byte{16, 6, 0, 0, 9, 0, 0, 0}
	plain := []byte("synthetic data..")
	body := bytes.Clone(plain)
	token, err := records.Send.WrapEx(ctx, records.SendSequence, [][]byte{header, body, trailer}, [][]byte{body})
	if err != nil {
		t.Fatal(err)
	}
	type request struct {
		Op      string `json:"op"`
		Header  []byte `json:"header"`
		Body    []byte `json:"body"`
		Trailer []byte `json:"trailer"`
		Token   []byte `json:"token"`
	}
	exchange(request{Op: "unwrap", Header: header, Body: body, Trailer: trailer, Token: token})
	if !response.Confidential || !bytes.Equal(response.Body, plain) {
		t.Fatal("independent MIT did not authenticate/decrypt client record")
	}
	header[2] = 2
	exchange(request{Op: "wrap", Header: header, Body: plain, Trailer: trailer})
	if !response.Confidential {
		t.Fatal("MIT response was not confidential")
	}
	body = bytes.Clone(response.Body)
	ok, err := records.Receive.UnwrapEx(ctx, records.ReceiveSequence, [][]byte{header, body, trailer}, [][]byte{body}, response.Token)
	if err != nil || !ok || !bytes.Equal(body, plain) {
		t.Fatalf("MIT response did not authenticate/decrypt: %v", err)
	}
	if err := encoder.Encode(struct {
		Op string `json:"op"`
	}{"close"}); err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("MIT fixture exit: %v, safe diagnostic=%s", err, diagnostic.String())
	}
	t.Log("offline MIT accepted raw DCE three-leg authentication and bidirectional confidential records; no RPC bind/KDC/AD qualification")
}
