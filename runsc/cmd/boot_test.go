package cmd

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/sentry/netgate"
)

func TestProcessNetGateConfig(t *testing.T) {
	tests := []struct {
		name         string
		config       *netgate.Config
		open         func(string) (int, error)
		clearCloexec func(int) error
		wantConfig   *netgate.Config
		wantFD       int
		wantErr      bool
	}{
		{
			name: "Success",
			config: &netgate.Config{
				Sink: netgate.SinkConfig{Name: "sink1", Type: "remote_uds", Path: "/tmp/sock1"},
			},
			open: func(path string) (int, error) {
				if path == "/tmp/sock1" {
					return 100, nil
				}
				return -1, errors.New("not found")
			},
			clearCloexec: func(fd int) error { return nil },
			wantConfig: &netgate.Config{
				Sink: netgate.SinkConfig{Name: "sink1", Type: "remote_uds", Path: "/proc/self/fd/100"},
			},
			wantFD:  100,
			wantErr: false,
		},
		{
			name: "OpenError",
			config: &netgate.Config{
				Sink: netgate.SinkConfig{Name: "sink1", Type: "remote_uds", Path: "/tmp/sock1"},
			},
			open: func(path string) (int, error) {
				return -1, errors.New("open error")
			},
			clearCloexec: func(fd int) error { return nil },
			wantConfig:   nil,
			wantFD:       -1,
			wantErr:      true,
		},
		{
			name: "IgnoreSetupError",
			config: &netgate.Config{
				Sink: netgate.SinkConfig{Name: "sink1", Type: "remote_uds", Path: "/tmp/sock1", IgnoreSetupError: true},
			},
			open: func(path string) (int, error) {
				return -1, errors.New("open error")
			},
			clearCloexec: func(fd int) error { return nil },
			wantConfig: &netgate.Config{
				Sink: netgate.SinkConfig{},
			},
			wantFD:  -1,
			wantErr: false,
		},
		{
			name: "ClearCloexecError",
			config: &netgate.Config{
				Sink: netgate.SinkConfig{Name: "sink1", Type: "remote_uds", Path: "/tmp/sock1"},
			},
			open: func(path string) (int, error) {
				return 100, nil
			},
			clearCloexec: func(fd int) error { return errors.New("fcntl error") },
			wantConfig:   nil,
			wantFD:       -1,
			wantErr:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conf := *tc.config // Copy to avoid mutating test case input if we reused it
			gotFD, err := processNetGateConfig(&conf, tc.open, tc.clearCloexec)
			if (err != nil) != tc.wantErr {
				t.Errorf("processNetGateConfig() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if tc.wantErr {
				return
			}

			if diff := cmp.Diff(tc.wantConfig, &conf); diff != "" {
				t.Errorf("config mismatch (-want +got):\n%s", diff)
			}
			if gotFD != tc.wantFD {
				t.Errorf("fd mismatch: got %d, want %d", gotFD, tc.wantFD)
			}
		})
	}
}
