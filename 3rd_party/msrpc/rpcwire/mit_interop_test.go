package rpcwire

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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
	"github.com/deploymenttheory/go-sdk-activedirectory/3rd_party/msrpc/rpcdce"
)

type qualificationMITRequest struct {
	Op      string `json:"op"`
	Token   []byte `json:"token"`
	Header  []byte `json:"header"`
	Body    []byte `json:"body"`
	Trailer []byte `json:"trailer"`
}
type qualificationMITReply struct {
	Major, Flags uint32
	Token, Body  []byte
	Confidential bool
}

// MIT is solely the offline test acceptor. Runtime transport/auth code uses no
// process helper. Each profile uses a fresh synthetic keytab, ticket and context.
func TestQualificationMITActualRPCBindAndProtectedDRSLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("ADSDK_RPC_MIT_INTEROP") != "1" {
		t.Skip("explicit offline Linux MIT interoperability fixture")
	}
	for _, profile := range []int32{17, 18} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) { qualificationMITActualRPC(t, profile) })
	}
}

func qualificationMITActualRPC(t *testing.T, profile int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	now := time.Now().UTC()
	kt := keytab.New()
	if err := kt.AddEntry("ldap/dc.example.test", "EXAMPLE.TEST", "PUBLIC synthetic offline fixture only", now, 1, profile); err != nil {
		t.Fatal(err)
	}
	encoded, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	keytabPath, configPath := filepath.Join(dir, "synthetic.keytab"), filepath.Join(dir, "krb5.conf")
	if err = os.WriteFile(keytabPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	clear(encoded)
	if err = os.WriteFile(
		configPath,
		[]byte("[libdefaults]\n default_realm = EXAMPLE.TEST\n dns_lookup_kdc = false\n dns_lookup_realm = false\n rdns = false\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	service, name := types.NewPrincipalName(2, "ldap/dc.example.test"), types.NewPrincipalName(1, "client")
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
	actor, err := rpcdce.NewClient(
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
	command := exec.CommandContext(ctx, "python3", "../rpcdce/testdata/mit_dce_peer.py", keytabPath, "ldap/dc.example.test@EXAMPLE.TEST")
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
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close(); cancel(); _ = command.Wait() }()
	encoder, decoder := json.NewEncoder(input), json.NewDecoder(bufio.NewReaderSize(output, 128*1024))
	exchange := func(request qualificationMITRequest) (reply qualificationMITReply, err error) {
		if err = encoder.Encode(request); err == nil {
			err = decoder.Decode(&reply)
		}
		return reply, err
	}
	raw, server := net.Pipe()
	defer raw.Close()
	defer server.Close()
	done := make(chan error, 1)
	bindFixture := qualificationWireFixture(t, "drsrwire", "drs-bind-response")
	infoFixture := qualificationWireFixture(t, "drsrwire", "kind0")
	go func() {
		defer server.Close()
		settings := NewTransport()
		settings.MaxRecvFrag, settings.MaxXmitFrag = 65535, 65535
		tr := &transport{settings: &settings, cc: NewBufferedConn(server, 65535)}
		frame := make([]byte, 65535)
		h, err := tr.ReadBuffer(ctx, frame)
		if err != nil {
			done <- err
			return
		}
		if h.PacketType != PacketTypeBind || h.CallID != 1 {
			done <- ErrMalformedFragment
			return
		}
		var syntax [20]byte
		copy(syntax[:], frame[32:52])
		accepted, err := exchange(qualificationMITRequest{Op: "accept", Token: frame[int(h.FragLength)-int(h.AuthLength) : h.FragLength]})
		if err != nil || accepted.Major != 1 {
			done <- errors.Join(errors.New("MIT did not continue real RPC bind"), err)
			return
		}
		pdu := make([]byte, 40)
		binary.LittleEndian.PutUint16(pdu, 4096)
		binary.LittleEndian.PutUint16(pdu[2:], 4096)
		pdu[12] = 1
		transfer := transferSyntax()
		copy(pdu[20:], transfer[:])
		ack, err := controlPacket(PacketTypeBindAck, 1, pdu, accepted.Token)
		if err != nil {
			done <- err
			return
		}
		ack[3] |= 4
		if _, err = server.Write(ack); err != nil {
			done <- err
			return
		}
		h, err = tr.ReadBuffer(ctx, frame)
		if err != nil {
			done <- err
			return
		}
		if h.PacketType != PacketTypeAuth3 || h.CallID != 2 {
			done <- ErrMalformedFragment
			return
		}
		accepted, err = exchange(qualificationMITRequest{Op: "accept", Token: frame[int(h.FragLength)-int(h.AuthLength) : h.FragLength]})
		if err != nil || accepted.Major != 0 || accepted.Flags&0x3e != 0x3e || accepted.Flags&1 != 0 {
			done <- errors.Join(errors.New("MIT DCE context not complete with required protection"), err)
			return
		}
		for i, stub := range [][]byte{bindFixture, infoFixture, make([]byte, 24)} {
			h, err = tr.ReadBuffer(ctx, frame)
			if err != nil {
				done <- err
				return
			}
			end := int(h.FragLength) - int(h.AuthLength) - 8
			request, err := exchange(
				qualificationMITRequest{Op: "unwrap", Header: frame[:24], Body: frame[24:end], Trailer: frame[end : end+8], Token: frame[end+8 : h.FragLength]},
			)
			if err != nil || !request.Confidential {
				done <- errors.Join(errors.New("MIT rejected actual protected RPC request"), err)
				return
			}
			data := request.Body[:len(request.Body)-int(frame[end+2])]
			if len(data) < 60 || !bytes.Equal(data[len(data)-40:len(data)-20], syntax[:]) || !bytes.Equal(data[len(data)-20:], transfer[:]) {
				done <- ErrNoSecurityContext
				return
			}
			if h.CallID != uint32(i+3) || binary.LittleEndian.Uint16(frame[22:]) != []uint16{0, 19, 1}[i] {
				done <- ErrMalformedFragment
				return
			}
			pad := (-len(stub)) & 15
			end = 24 + len(stub) + pad
			response := make([]byte, end+8+76)
			response[0], response[2], response[3], response[4] = 5, 2, 3, 16
			binary.LittleEndian.PutUint16(response[8:], uint16(len(response)))
			binary.LittleEndian.PutUint16(response[10:], 76)
			binary.LittleEndian.PutUint32(response[12:], h.CallID)
			copy(response[24:], stub)
			trailer := response[end : end+8]
			trailer[0], trailer[1], trailer[2] = 16, 6, byte(pad)
			binary.LittleEndian.PutUint32(trailer[4:], 1)
			wrapped, err := exchange(qualificationMITRequest{Op: "wrap", Header: response[:24], Body: response[24:end], Trailer: trailer})
			if err != nil || !wrapped.Confidential || len(wrapped.Token) != 76 {
				done <- errors.Join(errors.New("MIT response record shape mismatch"), err)
				return
			}
			copy(response[24:end], wrapped.Body)
			copy(response[end+8:], wrapped.Token)
			if _, err = server.Write(response); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	client, err := Bind(ctx, raw, actor, DirectoryReplication, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := client.BindDiagnostics(ctx)
	if err != nil || bound.Status != 0 {
		t.Fatal(bound, err)
	}
	observed, err := client.ReadReplicationInfo(ctx, bound.Handle, 0, nil)
	if err != nil || len(observed.Neighbors) != 1 || observed.Neighbors[0].LastObjectUSN != -9 {
		t.Fatal(observed, err)
	}
	if status, err := client.UnbindDiagnostics(ctx, bound.Handle); err != nil || status != 0 {
		t.Fatal(status, err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = encoder.Encode(qualificationMITRequest{Op: "close"}); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	if err = command.Wait(); err != nil {
		t.Fatalf("MIT offline fixture exit: %v; safe diagnostic=%s", err, diagnostic.String())
	}
	t.Log("offline independent MIT accepted actual RPC BIND/AUTH3 and protected DRS bind/query/unbind; synthetic DRS peer, no KDC or AD claim")
}
