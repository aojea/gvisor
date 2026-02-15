# NetGate: Zero Trust Network Gate

[TOC]

## Overview

NetGate is a gVisor feature designed to enable Zero Trust networking architectures by transparently intercepting and ensuring traffic from sandboxed applications flows through a trusted control point.

Unlike tradition network interception which often relies on `iptables` or specialized network plugins, NetGate operates directly within the gVisor kernel (`netstack`). This allows for:

*   **Transparent Interception**: Applications are unaware they are being intercepted.
*   **Identity-Aware Routing**: Decisions can be based on sandboxed identity (e.g., UID/GID) not just network 5-tuple.
*   **Secure Handover**: Traffic is handed over to a local proxy (like Envoy) via a secure Unix Domain Socket (UDS), avoiding the overhead and complexity of TCP/IP stack traversal for local sidecars.
*   **Preserved Metadata**: Original connection metadata (Source IP, Destination IP, etc.) is preserved and passed to the proxy using the PROXY Protocol v2.

## Configuration

NetGate is configured via the `--pod-init-config` flag passed to `runsc`. In a Kubernetes environment, this is typically handled by the container runtime interface (CRI) or via annotations that `runsc` interprets (depending on your specific `runsc` configuration).

The configuration is a JSON object under the `network_gate` key.

### Configuration Structure

```json
{
  "network_gate": {
    "policy": "redirect_all",
    "sinks": [
      {
        "name": "primary_sidecar",
        "type": "remote_uds",
        "path": "/var/run/secrets/netgate/proxy.sock",
        "ignore_setup_error": false
      }
    ],
    "bypass_rules": [
      {
        "description": "Bypass for local DNS",
        "match": {
          "dst_net": "127.0.0.1/32"
        }
      },
      {
        "description": "Bypass for root user",
        "match": {
          "uid": 0
        }
      }
    ]
  }
}
```

### Fields

*   **`policy`**: Determines the default action. Currently, only `"redirect_all"` is supported, which implies strict interception unless bypassed.
*   **`sinks`**: A list of destinations where intercepted traffic is sent.
    *   **`name`**: Unique identifier for the sink.
    *   **`type`**: The type of sink. Currently supported: `"remote_uds"`.
    *   **`path`**: File system path to the UDS socket (must be accessible to `runsc`).
    *   **`ignore_setup_error`**: If true, `runsc` will not fail boot if the sink cannot be initialized (e.g., socket missing).
*   **`bypass_rules`**: A list of rules that allow specific traffic to bypass NetGate and use the default network path.
    *   **`match`**: Criteria for matching.
        *   **`uid`**: Match the effective User ID of the process initiating the connection.
        *   **`dst_net`**: Match the destination IP address against a CIDR block (e.g., "10.0.0.0/8").

## Architecture

When an application calls `connect()`, NetGate evaluates the request:

1.  **Bypass Check**: If the request matches any `bypass_rules`, it proceeds through the standard host network path (if allowed by other sandbox constraints).
2.  **Interception**: If not bypassed, and a Sink is configured, the connection is intercepted.
3.  **Splice**: `netstack` establishes a specialized connection that forwards payload data directly to the configured Sink.
4.  **Metadata Handover**: Before sending any application data, NetGate writes a **PROXY Protocol v2** header to the sink. This allows the receiving proxy (e.g., Envoy) to see the original source and destination addresses as if it were the original router.

## Sinks

### Unix Domain Socket (remote_uds)

This sink type connects to a listening Unix Domain Socket on the host (or in a shared volume context).

*   **Protocol**: standard stream (SOCK_STREAM).
*   **Framing**: PROXY Protocol v2 header followed by raw TCP stream.
*   **Use Case**: Ideal for sidecar proxies like Envoy running on the same node but outside the sandbox (or in a separate container sharing a UDS volume).
