// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netgate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Config represents the configuration to apply during pod creation.
// It mirrors the JSON structure passed via --pod-init-config within the "network_gate" field.
type Config struct {
	Policy      string       `json:"policy"`
	Sinks       []SinkConfig `json:"sinks"`
	BypassRules []Rule       `json:"bypass_rules"`
}

// SinkConfig describes a sink configuration.
type SinkConfig struct {
	Name             string `json:"name"`
	Type             string `json:"type"` // e.g., "remote_uds"
	Path             string `json:"path"` // Path to the UDS socket
	IgnoreSetupError bool   `json:"ignore_setup_error"`
}

// Rule describes a bypass rule.
type Rule struct {
	Description string    `json:"description"`
	Match       RuleMatch `json:"match"`
}

// RuleMatch criteria for bypass.
type RuleMatch struct {
	UID    *uint32 `json:"uid,omitempty"`
	DstNet string  `json:"dst_net,omitempty"` // CIDR notation
}

// LoadConfig loads a Config struct from a reader.
func LoadConfig(reader io.Reader) (*Config, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	config := &Config{}
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}
	if err := config.Valid(); err != nil {
		return nil, err
	}
	return config, nil
}

// LoadConfigFromFile loads a Config struct from a file.
func LoadConfigFromFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadConfig(f)
}

// Valid validates the configuration.
func (c *Config) Valid() error {
	if c.Policy != "redirect_all" && c.Policy != "" {
		return fmt.Errorf("unknown policy: %q", c.Policy)
	}
	return nil
}
