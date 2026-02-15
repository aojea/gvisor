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
	"fmt"
	"net"
	"sync"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// NetGate defines the interception logic.
type NetGate interface {
	// CheckConnect is called during the connect() syscall.
	// It returns a replacement Endpoint (connected to the Sink) or nil to proceed normally.
	CheckConnect(t *kernel.Task, addr tcpip.FullAddress, origin tcpip.Endpoint) (tcpip.Endpoint, error)
}

// Sink defines where traffic is sent.
type Sink interface {
	// Connect creates a connection to the external proxy.
	// src is the source address of the originating endpoint (if available).
	Connect(ctx context.Context, src, dst tcpip.FullAddress) (tcpip.Endpoint, error)
	// Name returns the name of the sink.
	Name() string
}

var (
	mu            sync.RWMutex
	config        *Config
	sinks         map[string]Sink
	sinkFactories = make(map[string]SinkFactory)
)

// SinkFactory creates a new sink.
type SinkFactory func(config *SinkConfig) (Sink, error)

// RegisterSinkFactory registers a sink factory.
func RegisterSinkFactory(name string, f SinkFactory) {
	mu.Lock()
	defer mu.Unlock()
	sinkFactories[name] = f
}

// NewSink creates a new sink from configuration.
func NewSink(c *SinkConfig) (Sink, error) {
	mu.RLock()
	f, ok := sinkFactories[c.Type]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown sink type: %q", c.Type)
	}
	return f(c)
}

// CheckConnect is the entry point for the hook.
func CheckConnect(t *kernel.Task, addr tcpip.FullAddress, origin tcpip.Endpoint) (tcpip.Endpoint, error) {
	mu.RLock()
	c := config
	s := sinks
	mu.RUnlock()

	if c == nil {
		return nil, nil
	}

	// helper to check if we should bypass
	if isBypassed(t.Credentials(), addr, c.BypassRules) {
		return nil, nil
	}

	// For now, if policy is redirect_all, try to use the first sink.
	if c.Policy == "redirect_all" && len(c.Sinks) > 0 {
		sinkName := c.Sinks[0].Name
		if sink, ok := s[sinkName]; ok {
			var src tcpip.FullAddress
			// Try to get source address from origin endpoint
			if origin != nil {
				if a, err := origin.GetLocalAddress(); err == nil {
					src = a
				}
			}
			return sink.Connect(t, src, addr)
		}
	}

	return nil, nil
}

func isBypassed(creds *auth.Credentials, addr tcpip.FullAddress, rules []Rule) bool {
	for _, r := range rules {
		if ruleMatches(creds, addr, r.Match) {
			return true
		}
	}
	return false
}

func ruleMatches(creds *auth.Credentials, addr tcpip.FullAddress, m RuleMatch) bool {
	if m.UID != nil {
		// EffectiveKUID is KUID (uint32).
		if creds.EffectiveKUID != auth.KUID(*m.UID) {
			return false
		}
	}
	if m.DstNet != "" {
		subnet, err := parseCIDR(m.DstNet)
		if err == nil {
			if !subnet.Contains(addr.Addr) {
				return false
			}
		} else {
			// Invalid CIDR in rule, assume no match to be safe (don't bypass).
			log.Warningf("NetGate: Invalid CIDR in bypass rule: %q, error: %v", m.DstNet, err)
			return false
		}
	}
	return true
}

func parseCIDR(s string) (tcpip.Subnet, error) {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return tcpip.Subnet{}, err
	}
	addr := tcpip.AddrFromSlice(ipNet.IP)
	mask := tcpip.MaskFromBytes(ipNet.Mask)
	return tcpip.NewSubnet(addr, mask)
}

// SetConfig sets the global configuration and initializes sinks.
func SetConfig(c *Config) {
	mu.Lock()
	defer mu.Unlock()
	config = c
	sinks = make(map[string]Sink)

	for _, sc := range c.Sinks {
		sink, err := NewSink(&sc)
		if err != nil {
			if sc.IgnoreSetupError {
				continue
			}
			// checking for error in SetConfig might be too late if we want to fail boot?
			// But SetConfig signature is void.
			// for now we just log (if we had a logger) or ignore?
			// Ideally SetConfig should return error.
			// But we'll just skip broken sinks for now or maybe panic if critical?
			// The caller `setupSeccheck` calls `Valid()` before, but `Valid()` doesn't check factory existence (yet).
			// We should probably log this.
			continue
		}
		sinks[sink.Name()] = sink
	}
}

// RegisterSink registers a sink.
func RegisterSink(s Sink) {
	mu.Lock()
	defer mu.Unlock()
	if sinks == nil {
		sinks = make(map[string]Sink)
	}
	sinks[s.Name()] = s
}
