package netgate

import (
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	gcontext "gvisor.dev/gvisor/pkg/context"
	unixtransport "gvisor.dev/gvisor/pkg/sentry/socket/unix/transport"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// EndpointAdapter adapts a unix.transport.Receiver and unix.transport.ConnectedEndpoint
// to a tcpip.Endpoint.
type EndpointAdapter struct {
	tcpip.DefaultSocketOptionsHandler

	receiver unixtransport.Receiver
	sender   unixtransport.ConnectedEndpoint
	queue    *waiter.Queue
	ops      tcpip.SocketOptions
	stype    linux.SockType
}

var _ tcpip.Endpoint = (*EndpointAdapter)(nil)

// NewEndpointAdapter creates a new EndpointAdapter.
func NewEndpointAdapter(stype linux.SockType, receiver unixtransport.Receiver, sender unixtransport.ConnectedEndpoint, queue *waiter.Queue) *EndpointAdapter {
	e := &EndpointAdapter{
		stype:    stype,
		receiver: receiver,
		sender:   sender,
		queue:    queue,
	}
	e.ops.InitHandler(e, &dummyStackHandler{}, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)
	return e
}

// Close implements tcpip.Endpoint.Close.
func (e *EndpointAdapter) Close() {
	e.receiver.Release(gcontext.Background())
	e.sender.Release(gcontext.Background())
}

// Abort implements tcpip.Endpoint.Abort.
func (e *EndpointAdapter) Abort() {
	e.Close()
}

// Read implements tcpip.Endpoint.Read.
func (e *EndpointAdapter) Read(w io.Writer, opts tcpip.ReadOptions) (tcpip.ReadResult, tcpip.Error) {
	// Allocate a buffer to read into.
	buf := make([]byte, 8192)
	data := [][]byte{buf}

	args := unixtransport.RecvArgs{
		Peek: opts.Peek,
	}

	// We use background context as Read is non-blocking (from Recv perspective)
	// or handled by caller? Recv is non-blocking.
	out, _, err := e.receiver.Recv(gcontext.Background(), data, args)
	if err != nil {
		return tcpip.ReadResult{}, translateSyserr(err)
	}

	if out.RecvLen == 0 {
		if e.receiver.IsRecvClosed() {
			return tcpip.ReadResult{}, &tcpip.ErrClosedForReceive{}
		}
		return tcpip.ReadResult{}, &tcpip.ErrWouldBlock{}
	}

	// Write to the writer
	n, ioErr := w.Write(buf[:out.RecvLen])
	if ioErr != nil {
		return tcpip.ReadResult{
			Count: n,
			Total: n,
		}, nil
	}

	return tcpip.ReadResult{
		Count: n,
		Total: n,
	}, nil
}

// Write implements tcpip.Endpoint.Write.
func (e *EndpointAdapter) Write(p tcpip.Payloader, opts tcpip.WriteOptions) (int64, tcpip.Error) {
	v := make([]byte, p.Len())
	if _, err := io.ReadFull(p, v); err != nil {
		return 0, &tcpip.ErrBadBuffer{}
	}

	data := [][]byte{v}

	// ConnectedEndpoint.Send(ctx, data, ctl, from)
	n, _, err := e.sender.Send(gcontext.Background(), data, unixtransport.ControlMessages{}, unixtransport.Address{})
	if err != nil {
		return n, translateSyserr(err)
	}
	return n, nil
}

// Connect implements tcpip.Endpoint.Connect.
func (e *EndpointAdapter) Connect(addr tcpip.FullAddress) tcpip.Error {
	return &tcpip.ErrAlreadyConnected{}
}

// Disconnect implements tcpip.Endpoint.Disconnect.
func (e *EndpointAdapter) Disconnect() tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Shutdown implements tcpip.Endpoint.Shutdown.
func (e *EndpointAdapter) Shutdown(flags tcpip.ShutdownFlags) tcpip.Error {
	return nil
}

// Listen implements tcpip.Endpoint.Listen.
func (e *EndpointAdapter) Listen(backlog int) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// Accept implements tcpip.Endpoint.Accept.
func (e *EndpointAdapter) Accept(peerAddr *tcpip.FullAddress) (tcpip.Endpoint, *waiter.Queue, tcpip.Error) {
	return nil, nil, &tcpip.ErrNotSupported{}
}

// Bind implements tcpip.Endpoint.Bind.
func (e *EndpointAdapter) Bind(addr tcpip.FullAddress) tcpip.Error {
	return &tcpip.ErrNotSupported{}
}

// GetLocalAddress implements tcpip.Endpoint.GetLocalAddress.
func (e *EndpointAdapter) GetLocalAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

// GetRemoteAddress implements tcpip.Endpoint.GetRemoteAddress.
func (e *EndpointAdapter) GetRemoteAddress() (tcpip.FullAddress, tcpip.Error) {
	return tcpip.FullAddress{}, nil
}

// Readiness implements tcpip.Endpoint.Readiness.
func (e *EndpointAdapter) Readiness(mask waiter.EventMask) waiter.EventMask {
	// We should probably delegate to queue or assume ready?
	// If the queue is notified, the waiter.Wait() returns.
	// But Readiness() is called to check state.
	// Receiver.Readable() logic?
	var ready waiter.EventMask
	if e.receiver.Readable() {
		ready |= waiter.ReadableEvents
	}
	// For Write, assume always writable?
	ready |= waiter.WritableEvents // Optimistic
	return ready & mask
}

// State implements tcpip.Endpoint.State.
func (e *EndpointAdapter) State() uint32 {
	switch e.stype {
	case linux.SOCK_STREAM:
		return uint32(tcp.StateEstablished)
	case linux.SOCK_DGRAM:
		return uint32(transport.DatagramEndpointStateConnected)
	default:
		return 0
	}
}

// WaitQueue implements tcpip.Endpoint.WaitQueue.
func (e *EndpointAdapter) WaitQueue() *waiter.Queue {
	return e.queue
}

// WakeupWriters implements tcpip.Endpoint.WakeupWriters.
func (e *EndpointAdapter) WakeupWriters() {
}

// SocketOptions implements tcpip.Endpoint.SocketOptions.
func (e *EndpointAdapter) SocketOptions() *tcpip.SocketOptions {
	return &e.ops
}

// Info implements tcpip.Endpoint.Info.
func (e *EndpointAdapter) Info() tcpip.EndpointInfo {
	return &dummyEndpointInfo{}
}

// Stats implements tcpip.Endpoint.Stats.
func (e *EndpointAdapter) Stats() tcpip.EndpointStats {
	return nil
}

// SetOwner implements tcpip.Endpoint.SetOwner.
func (e *EndpointAdapter) SetOwner(owner tcpip.PacketOwner) {
}

// LastError implements tcpip.Endpoint.LastError.
func (e *EndpointAdapter) LastError() tcpip.Error {
	return nil
}

// ModerateRecvBuf implements tcpip.Endpoint.ModerateRecvBuf.
func (e *EndpointAdapter) ModerateRecvBuf(copied int) {}

// SetSockOpt implements tcpip.Endpoint.SetSockOpt.
func (e *EndpointAdapter) SetSockOpt(opt tcpip.SettableSocketOption) tcpip.Error {
	return nil
}

// SetSockOptInt implements tcpip.Endpoint.SetSockOptInt.
func (e *EndpointAdapter) SetSockOptInt(opt tcpip.SockOptInt, v int) tcpip.Error {
	return nil
}

// GetSockOpt implements tcpip.Endpoint.GetSockOpt.
func (e *EndpointAdapter) GetSockOpt(opt tcpip.GettableSocketOption) tcpip.Error {
	return nil
}

// GetSockOptInt implements tcpip.Endpoint.GetSockOptInt.
func (e *EndpointAdapter) GetSockOptInt(opt tcpip.SockOptInt) (int, tcpip.Error) {
	return 0, nil
}

func translateSyserr(err *syserr.Error) tcpip.Error {
	if err == nil {
		return nil
	}
	if err == syserr.ErrWouldBlock {
		return &tcpip.ErrWouldBlock{}
	}
	if err == syserr.ErrConnectionReset {
		return &tcpip.ErrConnectionReset{}
	}
	if err == syserr.ErrBrokenPipe {
		return &tcpip.ErrClosedForSend{}
	}
	// TODO: Add more mappings
	return &tcpip.ErrInvalidEndpointState{}
}

type dummyStackHandler struct{}

func (*dummyStackHandler) Option(any) tcpip.Error { return nil }
func (*dummyStackHandler) TransportProtocolOption(tcpip.TransportProtocolNumber, tcpip.GettableTransportProtocolOption) tcpip.Error {
	return nil
}

type dummyEndpointInfo struct{}

func (*dummyEndpointInfo) IsEndpointInfo() {}
