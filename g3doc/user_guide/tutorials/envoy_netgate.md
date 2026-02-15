# Tutorial: Zero Trust Networking with NetGate and Envoy

[TOC]

This tutorial demonstrates how to implement a **Zero Trust** networking architecture using gVisor's **NetGate**.

In this architecture:
1.  **Untrusted Workload**: Runs inside a gVisor Sandbox (Pod). It cannot access the host network directly.
2.  **Trusted Proxy (Envoy)**: Runs on the **Host Network** (as a DaemonSet). It acts as the secure gateway for all outgoing traffic.
3.  **Secure Channel**: Traffic is transparently intercepted by NetGate inside gVisor and securely spliced to the Envoy proxy via a Unix Domain Socket (UDS).

This model ensures that the untrusted application cannot bypass the proxy and has no direct access to the host's TCP/IP stack.

## Prerequisites

*   A Kubernetes cluster (e.g., GKE or Kind).
*   gVisor (`runsc`) installed and configured as a RuntimeClass (e.g., `gvisor`).
*   `kubectl` command-line tool.

> [!NOTE]
> NetGate requires `runsc` to be configured with the `--pod-init-config` flag. In this tutorial, we assume you can pass this modification via a JSON config file or annotation depending on your `runsc` installation.

## Step 1: Deploy Trusted Envoy Proxy (DaemonSet)

We deploy Envoy as a **DaemonSet** with `hostNetwork: true`. This allows it to listen on a host path (e.g., `/var/run/netgate/proxy.sock`) and forward traffic to the outside world.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: envoy-config
  namespace: default
data:
  envoy.yaml: |
    static_resources:
      listeners:
      - name: netgate_listener
        address:
          pipe:
            path: "/var/run/netgate/proxy.sock"
            mode: 0666
        listener_filters:
        - name: envoy.filters.listener.proxy_protocol
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol
        filter_chains:
        - filters:
          - name: envoy.filters.network.tcp_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: ingress_tcp
              cluster: echo_service
      clusters:
      - name: echo_service
        connect_timeout: 0.25s
        type: LOGICAL_DNS
        lb_policy: ROUND_ROBIN
        load_assignment:
          cluster_name: echo_service
          endpoints:
          - lb_endpoints:
            - endpoint:
                address:
                  socket_address:
                    address: postman-echo.com
                    port_value: 80
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: envoy-gateway
  namespace: default
  labels:
    app: envoy-gateway
spec:
  selector:
    matchLabels:
      app: envoy-gateway
  template:
    metadata:
      labels:
        app: envoy-gateway
    spec:
      hostNetwork: true
      containers:
      - name: envoy
        image: envoyproxy/envoy:v1.26-latest
        command: ["envoy", "-c", "/etc/envoy/envoy.yaml"]
        securityContext:
          runAsUser: 0 # Needed to write to /var/run/netgate if created by root, or adjust permissions
        volumeMounts:
        - name: netgate-sockets
          mountPath: /var/run/netgate
        - name: envoy-config
          mountPath: /etc/envoy
      volumes:
      - name: netgate-sockets
        hostPath:
          path: /var/run/netgate
          type: DirectoryOrCreate
      - name: envoy-config
        configMap:
          name: envoy-config
```

## Step 2: Configure NetGate

Define the policy to redirect traffic to the socket created by Envoy.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: netgate-config
  namespace: default
data:
  config.json: |
    {
      "network_gate": {
        "policy": "redirect_all",
        "sinks": [
          {
            "name": "host_envoy",
            "type": "remote_uds",
            "path": "/var/run/netgate/proxy.sock",
            "ignore_setup_error": false
          }
        ],
        "bypass_rules": [
          {
            "description": "Bypass local loopback",
            "match": {
              "dst_net": "127.0.0.1/32"
            }
          }
        ]
      }
    }
```

## Step 3: Deploy Untrusted Workload

Deploy the application using the `gvisor` RuntimeClass. Note that this Pod **does not** need any sidecars or special network privileges. It simply attempts to connect to the internet, and NetGate transparently tunnels it to the Envoy on the host.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: netgate-client
  namespace: default
  annotations:
    # This annotation tells runsc where to find the config.
    # The path must be accessible to runsc on the host.
    # Alternatively, mounting the configmap and pointing to the mount path works 
    # if runsc is configured to look there.
    # Here we assume we mount the config into the container at /etc/netgate/config.json
    # AND pass that path to runsc via annotation or existing flag infrastructure.
    io.gvisor.pod-init-config: "/etc/netgate/config.json"
spec:
  runtimeClassName: gvisor
  volumes:
  - name: netgate-config
    configMap:
      name: netgate-config
  containers:
  - name: app
    image: alpine
    command: ["sh", "-c", "apk add curl && sleep 3600"]
    volumeMounts:
    - name: netgate-config
      mountPath: /etc/netgate
```

> [!NOTE]
> The `io.gvisor.pod-init-config` annotation usage depends on how your cluster's CRI and `runsc` wrapper are set up. Some setups might require passing the flag `-pod-init-config=/path/to/config` via `runtimeArgs`.

## Step 4: Verify Zero Trust

1.  **Apply manifests**:
    ```bash
    kubectl apply -f envoy-daemonset.yaml
    kubectl apply -f netgate-config.yaml
    kubectl apply -f workload.yaml
    ```

2.  **Test Internal Access (Blocked/Redirected)**:
    Since our Envoy is only configured to proxy `postman-echo.com`, attempts to access other internal IPs or unauthorized services will fail (or be routed to Envoy and dropped if no route matches), effectively enforcing the policy.

3.  **Test External Access (Proxied)**:
    ```bash
    kubectl exec -it netgate-client -- curl -v http://1.1.1.1/get
    ```
    Even though we requested `1.1.1.1`, the connection is hijacked by NetGate -> UDS -> Envoy. Envoy sees the request.
    *   If Envoy is configured to `tcp_proxy` everything to `postman-echo` (as in this simple example), you will get a response from `postman-echo`.
    *   This proves interception is working. If it weren't, you would reach `1.1.1.1` (Cloudflare) directly.

## Architecture Diagram

```mermaid
graph TD
    subgraph "Host Node"
        Envoy[Envoy Proxy (DaemonSet)] -- Host Network --> Internet
        Socket(Unix Domain Socket<br/>/var/run/netgate/proxy.sock)
        Envoy <--> Socket
    end

    subgraph "gVisor Sandbox (User Pod)"
        App[Untrusted App] -- connect() --> NetStack
        NetStack -- Filter/Redirect --> NetGate
    end

    NetGate -- "Spliced Connection (UDS)" --> Socket

    style Envoy fill:#e1f5fe,stroke:#01579b
    style App fill:#ffebee,stroke:#b71c1c
    style NetGate fill:#fff3e0,stroke:#e65100,stroke-dasharray: 5 5
```
