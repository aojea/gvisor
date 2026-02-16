package netgate

import (
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// MockSink implements Sink for testing.
type MockSink struct {
	name string
}

func (m *MockSink) Connect(ctx context.Context, src, dst tcpip.FullAddress) (tcpip.Endpoint, error) {
	return nil, nil
}

func (m *MockSink) Name() string {
	return m.name
}

func TestRegisterSinkFactory(t *testing.T) {
	called := false
	RegisterSinkFactory("test_sink", func(c *SinkConfig) (Sink, error) {
		called = true
		return &MockSink{name: "test_instance"}, nil
	})

	cfg := &Config{
		Sink: SinkConfig{
			Name: "test_sink_instance",
			Type: "test_sink",
		},
	}

	SetConfig(cfg)

	if !called {
		t.Error("Factory not called")
	}

	if sink.Name() != "test_sink_instance" {
		t.Errorf("Sink name mismatch: got %q, want %q", sink.Name(), "test_sink_instance")
	}
}
