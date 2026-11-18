package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func kdcContextCause(ctx context.Context) error {
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (cl *Client) kdcAddresses(realm, network string) (map[int]string, error) {
	ctx := cl.settings.context()
	if cause := kdcContextCause(ctx); cause != nil {
		return nil, cause
	}
	for _, configured := range cl.Config.Realms {
		if configured.Realm == realm && len(configured.KDC) != 0 {
			_, addresses, err := cl.Config.GetKDCs(realm, network == "tcp")
			return addresses, err
		}
	}
	if !cl.Config.LibDefaults.DNSLookupKDC {
		return nil, errors.New("explicit realm has no configured KDC and DNS discovery is disabled")
	}
	_, servers, err := net.DefaultResolver.LookupSRV(ctx, "kerberos", network, realm)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("KDC discovery failed: %w", err), kdcContextCause(ctx))
	}
	addresses := make(map[int]string, len(servers))
	for _, server := range servers {
		host := strings.TrimSuffix(server.Target, ".")
		if host == "" || server.Port == 0 {
			continue
		}
		addresses[len(addresses)+1] = net.JoinHostPort(host, strconv.Itoa(int(server.Port)))
	}
	if len(addresses) == 0 {
		return nil, errors.New("explicit realm has no usable KDC discovery records")
	}
	return addresses, nil
}

func dialSendKDCContext(ctx context.Context, network string, kdcs map[int]string, request []byte) ([]byte, error) {
	var attempts []error
	for i := 1; i <= len(kdcs); i++ {
		if cause := kdcContextCause(ctx); cause != nil {
			return nil, errors.Join(errors.Join(attempts...), cause)
		}
		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.DialContext(ctx, network, kdcs[i])
		if err != nil {
			attempts = append(attempts, err)
			continue
		}
		deadline := time.Now().Add(5 * time.Second)
		if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
			deadline = callerDeadline
		}
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			attempts = append(attempts, err)
			continue
		}
		retired := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			_ = conn.Close()
			close(retired)
		})
		var response []byte
		if network == "udp" {
			udp, ok := conn.(*net.UDPConn)
			if !ok {
				err = errors.New("KDC UDP transport returned an invalid connection")
				_ = conn.Close()
			} else {
				response, err = sendUDP(udp, request)
			}
		} else {
			response, err = sendTCP(conn, request)
		}
		if !stop() {
			<-retired
		}
		if cause := kdcContextCause(ctx); cause != nil {
			return nil, errors.Join(err, cause)
		}
		if err == nil {
			return response, nil
		}
		attempts = append(attempts, err)
	}
	return nil, fmt.Errorf("KDC exchange failed: %w", errors.Join(attempts...))
}
