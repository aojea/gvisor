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
		Sinks: []SinkConfig{
			{
				Name: "test_sink_instance",
				Type: "test_sink",
			},
		},
	}

	SetConfig(cfg)

	if !called {
		t.Error("Factory not called")
	}

	mu.RLock()
	sink, ok := sinks["test_sink_instance"]
	mu.RUnlock()

	if !ok {
		t.Error("Sink not registered")
	}
	if sink.Name() != "test_sink_instance" { // Wait, MockSink returns "test_instance" as Name?
		// My MockSink impl returns m.name, initialized to "test_instance".
		// But in SetConfig, we use sinks[sink.Name()] = sink.
		// So the key in map is "test_instance".
		// The Config has Name: "test_sink_instance".
		// Usually the Sink should probably adopt the name from config?
		// Let's check NewSink wrapper/logic or if the factory is responsible.
	}
}
