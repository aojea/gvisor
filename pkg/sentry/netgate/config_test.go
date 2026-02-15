package netgate

import (
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	testCases := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name:    "valid config",
			json:    `{"policy": "redirect_all", "sinks": [{"name": "s1", "type": "uds", "path": "/tmp/s.sock"}]}`,
			wantErr: false,
		},
		{
			name:    "empty config",
			json:    `{}`,
			wantErr: false,
		},
		{
			name:    "unknown field",
			json:    `{"policy": "redirect_all", "unknown": "field"}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			json:    `{"policy": "redirect_all",`,
			wantErr: true,
		},
		{
			name:    "invalid policy",
			json:    `{"policy": "invalid_policy"}`,
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(strings.NewReader(tc.json))
			if (err != nil) != tc.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
