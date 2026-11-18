// Command sasl-peer injects one bounded protected-stream fault in an owned AD
// lab guest. It records counts and termination facts, never LDAP or GSS tokens.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const maximumRecord = 16 * 1024 * 1024

type observations struct {
	RunID                       string `json:"run_id"`
	Scenario                    string `json:"scenario"`
	ClientRecords               uint64 `json:"client_records"`
	ServerRecords               uint64 `json:"server_records"`
	ClientProtectedRecords      uint64 `json:"client_protected_records"`
	ServerProtectedRecords      uint64 `json:"server_protected_records"`
	ClientRecordsAfterInjection uint64 `json:"client_records_after_injection"`
	Injected                    bool   `json:"injected"`
	FaultRecordForwarded        bool   `json:"fault_record_forwarded"`
	ClientEOFAfterInjection     bool   `json:"client_eof_after_injection"`
	FirstTerminatingDirection   string `json:"first_terminating_direction"`
	Termination                 string `json:"termination"`
	Complete                    bool   `json:"complete"`
}

type relayState struct {
	protected      atomic.Bool
	injected       atomic.Bool
	faultForwarded atomic.Bool
	clientEOF      atomic.Bool
	clientRecords  atomic.Uint64
	serverRecords  atomic.Uint64
	clientFrames   atomic.Uint64
	serverFrames   atomic.Uint64
	afterFault     atomic.Uint64
}

type termination struct{ direction, reason string }

func main() {
	listen := flag.String("listen", "10.77.23.10:31389", "owned DC1 lab address and high port")
	scenario := flag.String("scenario", "pass", "pass, tampered, reordered, truncated-prefix or truncated-body")
	runID := flag.String("run-id", "", "owned ASCII run identifier")
	ready := flag.String("ready", "", "fresh readiness JSON path")
	output := flag.String("output", "", "fresh final JSON path")
	flag.Parse()
	if err := run(*listen, *scenario, *runID, *ready, *output); err != nil {
		fmt.Fprintln(os.Stderr, "owned SASL peer failed; inspect count-only evidence")
		os.Exit(1)
	}
}

func validScenario(scenario string) bool {
	switch scenario {
	case "pass", "tampered", "reordered", "truncated-prefix", "truncated-body":
		return true
	default:
		return false
	}
}

func run(address, scenario, runID, readyPath, outputPath string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || (host != "10.77.23.10" && host != "127.0.0.1") || port != "31389" ||
		!validScenario(scenario) || len(runID) == 0 || len(runID) > 40 || strings.IndexFunc(runID, func(c rune) bool {
		return c > 127 || !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-')
	}) != -1 || readyPath == "" || outputPath == "" || readyPath == outputPath {
		return errors.New("invalid owned SASL peer inputs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	if err := writeJSON(readyPath, map[string]string{"run_id": runID, "listen": listener.Addr().String(), "scenario": scenario}); err != nil {
		return err
	}
	client, err := listener.Accept()
	if err != nil {
		return err
	}
	_ = listener.Close() // Exactly one client connection; no fallback listener.
	defer client.Close()
	backend, err := (&net.Dialer{}).DialContext(ctx, "tcp", "127.0.0.1:389")
	if err != nil {
		return err
	}
	defer backend.Close()
	result := relay(ctx, client, backend, scenario)
	result.RunID, result.Scenario = runID, scenario
	return writeJSON(outputPath, result)
}

func writeJSON(path string, value any) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(value)
	return errors.Join(err, file.Close())
}

func relay(ctx context.Context, client, backend net.Conn, scenario string) observations {
	state := &relayState{}
	done := make(chan termination, 2)
	stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = backend.Close() })
	defer stop()
	go func() { done <- relayClient(client, backend, state) }()
	go func() { done <- relayServer(backend, client, state, scenario) }()
	first := <-done
	_ = client.Close()
	_ = backend.Close()
	<-done
	return observations{
		ClientRecords: state.clientRecords.Load(), ServerRecords: state.serverRecords.Load(),
		ClientProtectedRecords: state.clientFrames.Load(), ServerProtectedRecords: state.serverFrames.Load(),
		ClientRecordsAfterInjection: state.afterFault.Load(), Injected: state.injected.Load(), FaultRecordForwarded: state.faultForwarded.Load(),
		ClientEOFAfterInjection:   state.clientEOF.Load(),
		FirstTerminatingDirection: first.direction, Termination: first.reason,
		Complete: ctx.Err() == nil && state.protected.Load() && state.clientFrames.Load() > 0 && state.serverFrames.Load() > 0 &&
			(scenario == "pass" || state.faultForwarded.Load()),
	}
}

func relayClient(client, backend net.Conn, state *relayState) termination {
	for {
		wire, protected, err := readRecord(client, state.protected.Load)
		if err != nil {
			clear(wire)
			if errors.Is(err, io.EOF) && state.injected.Load() {
				state.clientEOF.Store(true)
			}
			return termination{"client", terminalReason(err)}
		}
		state.clientRecords.Add(1)
		if protected {
			state.clientFrames.Add(1)
			if state.injected.Load() {
				state.afterFault.Add(1)
			}
		}
		err = writeRecord(backend, wire)
		clear(wire)
		if err != nil {
			return termination{"client", "upstream-write"}
		}
	}
}

func relayServer(backend, client net.Conn, state *relayState, scenario string) termination {
	for {
		wire, protected, err := readRecord(backend, state.protected.Load)
		if err != nil {
			clear(wire)
			return termination{"server", terminalReason(err)}
		}
		state.serverRecords.Add(1)
		if !protected && successfulBind(wire) {
			state.protected.Store(true) // Before the client receives acceptance.
		}
		if protected {
			state.serverFrames.Add(1)
		}
		truncate := false
		wholeWire := wire
		if protected && scenario != "pass" && !state.injected.Swap(true) {
			switch scenario {
			case "tampered":
				wire[len(wire)-1] ^= 1
			case "reordered":
				next, nextProtected, readErr := readRecord(backend, state.protected.Load)
				if readErr != nil || !nextProtected {
					clear(wire)
					clear(next)
					return termination{"server", "reorder-input"}
				}
				state.serverRecords.Add(1)
				state.serverFrames.Add(1)
				err = writeRecord(client, next)
				if err == nil {
					state.faultForwarded.Store(true)
				}
				clear(next)
			case "truncated-prefix":
				wire = wire[:3]
				truncate = true
			case "truncated-body":
				wire = wire[:len(wire)-1]
				truncate = true
			}
		}
		if err == nil {
			err = writeRecord(client, wire)
			if err == nil && state.injected.Load() {
				state.faultForwarded.Store(true)
			}
		}
		clear(wholeWire)
		if truncate {
			return termination{"server", "intentional-truncation"}
		}
		if err != nil {
			return termination{"server", "downstream-write"}
		}
	}
}

func terminalReason(err error) string {
	if errors.Is(err, io.EOF) {
		return "eof"
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return "truncated"
	}
	return "transport-or-frame-error"
}

func writeRecord(writer io.Writer, wire []byte) error {
	n, err := writer.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	return err
}

func readRecord(reader io.Reader, protected func() bool) ([]byte, bool, error) {
	var header [6]byte
	if _, err := io.ReadFull(reader, header[:1]); err != nil {
		return nil, false, err
	}
	framed := protected() // The phase may change while the first read blocks.
	headerLength := 2
	var bodyLength uint32
	if framed {
		headerLength = 4
		if _, err := io.ReadFull(reader, header[1:4]); err != nil {
			return nil, true, err
		}
		bodyLength = binary.BigEndian.Uint32(header[:4])
		if bodyLength < 16 {
			return nil, true, errors.New("invalid SASL record")
		}
	} else {
		if header[0] != 0x30 {
			return nil, false, errors.New("invalid LDAP record")
		}
		if _, err := io.ReadFull(reader, header[1:2]); err != nil {
			return nil, false, err
		}
		bodyLength = uint32(header[1])
		if header[1]&128 != 0 {
			count := int(header[1] & 127)
			if count == 0 || count > 4 {
				return nil, false, errors.New("invalid LDAP record length")
			}
			if _, err := io.ReadFull(reader, header[2:2+count]); err != nil {
				return nil, false, err
			}
			bodyLength = 0
			for _, octet := range header[2 : 2+count] {
				bodyLength = bodyLength<<8 | uint32(octet)
			}
			headerLength += count
		}
	}
	if bodyLength > maximumRecord-uint32(headerLength) {
		return nil, framed, errors.New("record exceeds fixture bound")
	}
	wire := make([]byte, headerLength+int(bodyLength))
	copy(wire, header[:headerLength])
	_, err := io.ReadFull(reader, wire[headerLength:])
	return wire, framed, err
}

func takeTLV(wire []byte, tag byte) (body, tail []byte, ok bool) {
	if len(wire) < 2 || wire[0] != tag {
		return nil, nil, false
	}
	length, offset := uint32(wire[1]), 2
	if wire[1]&128 != 0 {
		count := int(wire[1] & 127)
		if count == 0 || count > 4 || len(wire) < 2+count {
			return nil, nil, false
		}
		length = 0
		for _, octet := range wire[2 : 2+count] {
			length = length<<8 | uint32(octet)
		}
		offset += count
	}
	if uint64(length) > uint64(len(wire)-offset) {
		return nil, nil, false
	}
	end := offset + int(length)
	return wire[offset:end], wire[end:], true
}

func successfulBind(wire []byte) bool {
	message, tail, ok := takeTLV(wire, 0x30)
	if !ok || len(tail) != 0 {
		return false
	}
	_, operation, ok := takeTLV(message, 2)
	if !ok {
		return false
	}
	bind, _, ok := takeTLV(operation, 0x61)
	if !ok {
		return false
	}
	code, _, ok := takeTLV(bind, 10)
	return ok && len(code) == 1 && code[0] == 0
}
