package netgate

import (
	"bytes"
	"encoding/hex"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestWriteProxyProtocolV2_IPv4(t *testing.T) {
	var buf bytes.Buffer
	src := tcpip.FullAddress{Addr: tcpip.AddrFromSlice([]byte{192, 168, 1, 1}), Port: 12345}
	dst := tcpip.FullAddress{Addr: tcpip.AddrFromSlice([]byte{10, 0, 0, 1}), Port: 80}

	if err := WriteProxyProtocolV2(&buf, src, dst); err != nil {
		t.Fatalf("WriteProxyProtocolV2 failed: %v", err)
	}

	// Expected header:
	// Sig: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
	// Ver|Cmd: \x21 (v2, LOGAL)
	// Fam|Proto: \x11 (AF_INET, STREAM)
	// Len: \x00\x0C (12 bytes)
	// SrcAddr: 192.168.1.1
	// DstAddr: 10.0.0.1
	// SrcPort: 12345 (0x3039)
	// DstPort: 80 (0x0050)

	expected := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21,
		0x11,
		0x00, 0x0C,
		192, 168, 1, 1,
		10, 0, 0, 1,
		0x30, 0x39,
		0x00, 0x50,
	}

	if !bytes.Equal(buf.Bytes(), expected) {
		t.Errorf("Result mismatch:\nGot:  %s\nWant: %s", hex.Dump(buf.Bytes()), hex.Dump(expected))
	}
}

func TestWriteProxyProtocolV2_IPv6(t *testing.T) {
	var buf bytes.Buffer
	// 2001:db8::1 -> 2001:db8::2
	srcIP := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstIP := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	src := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(srcIP), Port: 443}
	dst := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(dstIP), Port: 8443}

	if err := WriteProxyProtocolV2(&buf, src, dst); err != nil {
		t.Fatalf("WriteProxyProtocolV2 failed: %v", err)
	}

	// Expected header:
	// Ver|Cmd: \x21
	// Fam|Proto: \x21 (AF_INET6, STREAM)
	// Len: \x00\x24 (36 bytes: 16+16+2+2)

	headerLen := 16 // fixed header + addrs/ports
	payloadLen := 16 + 16 + 2 + 2
	expectedLen := headerLen + payloadLen

	if buf.Len() != expectedLen {
		t.Errorf("Expected length %d, got %d", expectedLen, buf.Len())
	}

	out := buf.Bytes()
	if out[12] != 0x21 {
		t.Errorf("Expected version/command 0x21, got 0x%x", out[12])
	}
	if out[13] != 0x21 { // AF_INET6 | STREAM
		t.Errorf("Expected family/proto 0x21, got 0x%x", out[13])
	}
}
