package netgate

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/waiter"
)

// UDSSink connects to a Unix Domain Socket proxy.
type UDSSink struct {
	Path string
}

// NewUDSSink creates a new UDSSink.
func NewUDSSink(path string) *UDSSink {
	return &UDSSink{Path: path}
}

// Name implements Sink.Name.
func (s *UDSSink) Name() string {
	return "remote_uds"
}

// Connect implements Sink.Connect.
func (s *UDSSink) Connect(ctx context.Context, src, dst tcpip.FullAddress) (tcpip.Endpoint, error) {
	// 1. Create socket
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	// 2. Connect
	sa := &unix.SockaddrUnix{Name: s.Path}
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// 3. Write PROXY header
	if err := WriteProxyProtocolV2(&fdWriter{fd: fd}, src, dst); err != nil {
		unix.Close(fd)
		return nil, err
	}

	// 4. Wrap in SCMConnectedEndpoint because we own the FD.
	queue := &waiter.Queue{}
	e, sysErr := transport.NewSCMEndpoint(fd, queue, s.Path)
	if sysErr != nil {
		unix.Close(fd)
		return nil, sysErr.ToError()
	}

	if err := e.Init(); err != nil {
		e.Release(ctx)
		return nil, err
	}

	return NewEndpointAdapter(linux.SockType(unix.SOCK_STREAM), e, e, queue), nil
}

type fdWriter struct {
	fd int
}

func (w *fdWriter) Write(p []byte) (int, error) {
	return unix.Write(w.fd, p)
}

func init() {
	RegisterSinkFactory("remote_uds", func(c *SinkConfig) (Sink, error) {
		return NewUDSSink(c.Path), nil
	})
}
