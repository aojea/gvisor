package netgate

import (
	"encoding/binary"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/tcpip"
	// For AF definitions if needed, or just use constants
)

// Implement PROXY Protocol v2 as specified in
// https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

// The binary header format starts with a constant 12 bytes block containing the
// protocol signature
var (
	proxyProtocolV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
)

const (
	// The next byte (the 13th one) is the protocol version and command.
	proxyProtocolV2Version      = 0x20
	proxyProtocolV2CommandProxy = 0x01
	proxyProtocolV2CommandLocal = 0x00
	// The 14th byte contains the transport protocol and address family. The highest 4
	// bits contain the address family, the lowest 4 bits contain the protocol.
	// Address family
	proxyProtocolV2FamilyAF_UNSPEC = 0x00
	proxyProtocolV2FamilyAF_INET   = 0x10
	proxyProtocolV2FamilyAF_INET6  = 0x20
	// Protocol
	proxyProtocolV2ProtocolUnknown  = 0x00
	proxyProtocolV2ProtocolStream   = 0x01
	proxyProtocolV2ProtocolDatagram = 0x02
)

// WriteProxyProtocolV2 writes the PROXY protocol v2 header to the writer.
func WriteProxyProtocolV2(w io.Writer, src, dst tcpip.FullAddress) error {
	if _, err := w.Write(proxyProtocolV2Signature); err != nil {
		return err
	}

	if _, err := w.Write([]byte{proxyProtocolV2Version | proxyProtocolV2CommandProxy}); err != nil {
		return err
	}

	var family byte

	proto := proxyProtocolV2ProtocolStream

	// Check IP versions
	srcLen := src.Addr.Len()
	dstLen := dst.Addr.Len()

	srcIPv4 := srcLen == 4
	dstIPv4 := dstLen == 4
	srcIPv6 := srcLen == 16
	dstIPv6 := dstLen == 16

	if srcIPv4 && dstIPv4 {
		family = byte(proxyProtocolV2FamilyAF_INET | proto)
	} else if srcIPv6 && dstIPv6 {
		family = byte(proxyProtocolV2FamilyAF_INET6 | proto)
	} else if srcLen == 0 || dstLen == 0 {
		family = byte(proxyProtocolV2CommandLocal)
	} else {
		return fmt.Errorf("address family mismatch or unsupported: len(src)=%d, len(dst)=%d", srcLen, dstLen)
	}

	if _, err := w.Write([]byte{family}); err != nil {
		return err
	}

	var length uint16
	if family == byte(proxyProtocolV2FamilyAF_INET|proto) {
		length = 12 // 4+4+2+2
	} else if family == byte(proxyProtocolV2FamilyAF_INET6|proto) {
		length = 36 // 16+16+2+2
	} else {
		length = 0
	}

	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}

	if length == 0 {
		return nil
	}

	// Addresses
	if srcIPv4 {
		b := src.Addr.As4()
		if _, err := w.Write(b[:]); err != nil {
			return err
		}
		bDst := dst.Addr.As4()
		if _, err := w.Write(bDst[:]); err != nil {
			return err
		}
	} else {
		b := src.Addr.As16()
		if _, err := w.Write(b[:]); err != nil {
			return err
		}
		bDst := dst.Addr.As16()
		if _, err := w.Write(bDst[:]); err != nil {
			return err
		}
	}

	// Ports
	if err := binary.Write(w, binary.BigEndian, src.Port); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, dst.Port); err != nil {
		return err
	}

	return nil
}
