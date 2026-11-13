//go:build windows && (amd64 || arm64)

package activedirectory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// Actual WinLDAP consumes binary and ranged responses from a loopback fixture.
// No authentication or real directory is involved. Native allocation counts
// cover message/value/name/BER ownership, including partial server errors.
func TestNativeMetadataWireAndControls(t *testing.T) {
	for _, mode := range []string{"attributes-ranged", "links-controls", "vectors", "missing", "denied", "partial-denied", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			kind := metadataAttribute
			var controls []string
			rounds := 1
			if mode == "attributes-ranged" {
				rounds = 2
			}
			if mode == "links-controls" {
				kind = metadataLink
				controls = []string{metadataShowDeleted, metadataShowDeactivated}
			}
			if mode == "vectors" {
				kind = metadataVector
			}
			done := make(chan error, 1)
			go func() { done <- serveMetadataWire(listener, kind, mode, rounds, controls) }()
			var counts searchNativeCounts
			client := searchWireClient(t, &searchWireFixture{listener: listener}, countedSearchAPI(&counts))
			var rows int
			objects, state := readMetadataValues(context.Background(), client, "CN=Object,DC=example,DC=test", kind, controls, func(value []byte) error {
				var err error
				switch kind {
				case metadataAttribute:
					_, err = decodeMetadataAttribute(value)
				case metadataLink:
					_, err = decodeMetadataLink(value)
				case metadataVector:
					_, err = decodeMetadataCursor(value)
				}
				if err == nil {
					rows++
				}
				return err
			})
			if err := client.Close(); err != nil {
				t.Error(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("metadata responder did not stop")
			}
			if counts != (searchNativeCounts{}) {
				t.Fatalf("native ownership leak: %+v", counts)
			}
			wantCode := uint32(0)
			switch mode {
			case "missing":
				wantCode = 32
			case "denied", "partial-denied":
				wantCode = 50
			}
			if wantCode != 0 {
				if state.Complete || !hasLDAPCode(state.Error, wantCode) {
					t.Fatalf("native error lost: %+v", state)
				}
				if mode == "partial-denied" && (rows != 1 || !state.Available) {
					t.Fatal("partial response lost")
				}
			} else if mode == "malformed" {
				if state.Complete || !errors.Is(state.Error, ErrInvalidResult) || len(objects) != 1 {
					t.Fatalf("malformed result %+v", state)
				}
			} else if !state.Complete || !state.Available || state.Error != nil || rows != rounds || len(objects) != rounds {
				t.Fatalf("rows=%d state=%+v", rows, state)
			}
		})
	}
}

func serveMetadataWire(listener net.Listener, kind, mode string, rounds int, wantControls []string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	for round := 0; round < rounds; round++ {
		packet, err := readSearchBER(conn)
		if err != nil {
			return err
		}
		id, rest, err := takeSearchBER(packet, 2)
		if err != nil {
			return err
		}
		request, encodedControls, err := takeSearchBER(rest, 0x63)
		if err != nil {
			return err
		}
		base, _, err := takeSearchBER(request, 4)
		if err != nil || string(base) != "CN=Object,DC=example,DC=test" {
			return fmt.Errorf("invalid metadata target: %v", err)
		}
		if len(wantControls) == 0 {
			if len(encodedControls) != 0 {
				return errors.New("unexpected controls")
			}
		} else {
			encodedControls, _, err = takeSearchBER(encodedControls, 0xa0)
			if err != nil {
				return err
			}
			for _, oid := range wantControls {
				var control []byte
				control, encodedControls, err = takeSearchBER(encodedControls, 0x30)
				if err != nil {
					return err
				}
				var actual []byte
				actual, rest, err = takeSearchBER(control, 4)
				if err != nil || string(actual) != oid {
					return errors.New("wrong metadata control")
				}
				critical, tail, err := takeSearchBER(rest, 1)
				// WinLDAP encodes a zeroed LDAP_BERVAL as an empty OCTET
				// STRING. No application control payload may be supplied.
				if len(tail) == 2 && tail[0] == 4 && tail[1] == 0 {
					tail = nil
				}
				if err != nil || len(critical) != 1 || critical[0] == 0 || len(tail) != 0 {
					return fmt.Errorf("metadata control must be critical and valueless: critical=%x tail=%x err=%v", critical, tail, err)
				}
			}
			if len(encodedControls) != 0 {
				return errors.New("unexpected additional control")
			}
		}
		code := byte(0)
		if mode == "missing" {
			code = 32
		}
		if mode == "denied" || mode == "partial-denied" {
			code = 50
		}
		if mode != "missing" && mode != "denied" {
			name := kind + ";binary"
			if rounds == 2 {
				if round == 0 {
					name += ";range=0-0"
				} else {
					name += ";range=1-*"
				}
			}
			value := metadataTestBlob(kind)
			if mode == "malformed" {
				value = []byte{0, 1, 2}
			}
			entry := searchBER(0x64, searchBER(4, base), searchBER(0x30, searchWireAttribute(name, value), searchWireAttribute("uSNChanged", []byte("100"))))
			if _, err = conn.Write(searchBER(0x30, searchBER(2, id), entry)); err != nil {
				return err
			}
		}
		if _, err = conn.Write(searchBER(0x30, searchBER(2, id), searchBER(0x65, []byte{10, 1, code, 4, 0, 4, 0}))); err != nil {
			return err
		}
	}
	// Wait for unbind, so a premature disconnect cannot hide a cleanup failure.
	packet, err := readSearchBER(conn)
	if err != nil {
		return err
	}
	_, rest, err := takeSearchBER(packet, 2)
	if err != nil || len(rest) == 0 || rest[0] != 0x42 {
		return errors.New("expected native unbind")
	}
	return nil
}
