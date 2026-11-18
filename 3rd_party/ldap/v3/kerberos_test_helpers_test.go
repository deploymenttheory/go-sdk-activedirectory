package ldap

import (
	"io"
	"net"
	"time"
)

type fakeReadConn struct{ r io.Reader }

func (c *fakeReadConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (*fakeReadConn) Write(p []byte) (int, error)      { return len(p), nil }
func (*fakeReadConn) Close() error                     { return nil }
func (*fakeReadConn) LocalAddr() net.Addr              { return nil }
func (*fakeReadConn) RemoteAddr() net.Addr             { return nil }
func (*fakeReadConn) SetDeadline(time.Time) error      { return nil }
func (*fakeReadConn) SetReadDeadline(time.Time) error  { return nil }
func (*fakeReadConn) SetWriteDeadline(time.Time) error { return nil }
