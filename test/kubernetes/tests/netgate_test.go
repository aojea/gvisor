// Copyright 2024 The gVisor Authors.
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
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/test/kubernetes/k8sctx/kubectlctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// TestNetGateE2E tests that NetGate properly intercepts and redirects traffic.
func TestNetGateE2E(t *testing.T) {
	ctx := context.Background()
	k8sCtx, err := kubectlctx.New(ctx)
	if err != nil {
		t.Fatalf("Failed to get kubernetes context: %v", err)
	}
	cluster, releaseFn := k8sCtx.Cluster(ctx, t)
	defer releaseFn()

	// 1. Create Echo Server (agnhost)
	echoImage, err := k8sCtx.ResolveImage(ctx, "registry.k8s.io/e2e-test-images/agnhost:2.53")
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}

	echoPodName := "echo-server"
	echoNamespace := testcluster.NamespaceDefault
	echoPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      echoPodName,
			Namespace: echoNamespace,
			Labels: map[string]string{
				"app": "echo-server",
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "agnhost",
					Image: echoImage,
					// Run netexec on port 8080
					Args: []string{"netexec", "--http-port=8080"},
					Ports: []v1.ContainerPort{
						{ContainerPort: 8080},
					},
				},
			},
		},
	}

	echoPod, err = cluster.ConfigurePodForRuntimeTestNodepool(ctx, echoPod)
	if err != nil {
		t.Fatalf("Failed to configure echo pod: %v", err)
	}
	echoPod, err = cluster.CreatePod(ctx, echoPod)
	if err != nil {
		t.Fatalf("Failed to create echo pod: %v", err)
	}
	defer cluster.DeletePod(ctx, echoPod)

	if err := cluster.WaitForPodRunning(ctx, echoPod); err != nil {
		t.Fatalf("Failed to wait for echo pod running: %v", err)
	}

	// Refetch pod to get IP
	echoPod, err = cluster.GetPod(ctx, echoPod)
	if err != nil {
		t.Fatalf("Failed to get echo pod: %v", err)
	}
	t.Logf("Echo Pod IP: %s", echoPod.Status.PodIP)

	// 2. Create Service for Echo Server
	echoService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "echo-service",
			Namespace: echoNamespace,
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{
				"app": "echo-server",
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   v1.ProtocolTCP,
					Port:       8080,
					TargetPort: StrIntOr(8080),
				},
			},
			Type: v1.ServiceTypeClusterIP,
		},
	}
	echoService, err = cluster.CreateService(ctx, echoService)
	if err != nil {
		t.Fatalf("Failed to create echo service: %v", err)
	}
	defer cluster.DeleteService(ctx, echoService)

	// Wait for Service IP
	if err := cluster.WaitForServiceReady(ctx, echoService); err != nil {
		t.Fatalf("Failed to wait for echo service ready: %v", err)
	}
	echoService, err = cluster.GetService(ctx, echoService)
	if err != nil {
		t.Fatalf("Failed to get echo service: %v", err)
	}
	echoServiceIP := echoService.Spec.ClusterIP
	t.Logf("Echo Service IP: %s", echoServiceIP)

	// 3. Create Envoy ConfigMap
	// We point Envoy to the Echo Service IP
	envoyYaml := fmt.Sprintf(`
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
    type: STATIC
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: echo_service
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: %s
                port_value: 8080
`, echoServiceIP)

	cm := &v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "envoy-config",
			Namespace: "default",
		},
		Data: map[string]string{
			"envoy.yaml": envoyYaml,
		},
	}
	_, err = cluster.CreateConfigMap(ctx, cm)
	if err != nil {
		t.Fatalf("Failed to create Envoy ConfigMap: %v", err)
	}
	defer cluster.DeleteConfigMap(ctx, cm)

	defer cluster.DeleteConfigMap(ctx, cm)

	// 5. NetGate Config
	// We intercept traffic to a dummy IP (1.2.3.4) on port 80
	// and redirect it to the UDS.
	netgateConfig := `
{
	"policy": "redirect_all",
	"rules": [
		{
			"action": "redirect",
			"redirect": {
				"target": "uds",
				"path": "/var/run/netgate/proxy.sock"
			},
			"filter": {
				"protocol": "tcp",
				"dst_ip": "1.2.3.4",
				"dst_port": 80
			}
		}
	]
}
`

	// 4. Create Envoy DaemonSet

	hostPathType := v1.HostPathDirectoryOrCreate
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "envoy-gateway",
			Namespace: "default",
			Labels: map[string]string{
				"app": "envoy-gateway",
			},
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "envoy-gateway",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "envoy-gateway",
					},
				},
				Spec: v1.PodSpec{
					// Use HostNetwork so we can easily bind mount the socket dir
					// and share it with the gVisor pod via hostPath.
					// Also avoids CNI complexity for the proxy listener.
					HostNetwork: true,
					InitContainers: []v1.Container{
						{
							Name:  "write-config",
							Image: "alpine",
							Command: []string{
								"/bin/sh", "-c",
								fmt.Sprintf("echo '%s' > /var/run/netgate/config.json && chmod 644 /var/run/netgate/config.json", netgateConfig),
							},
							VolumeMounts: []v1.VolumeMount{
								{
									Name:      "netgate-sockets",
									MountPath: "/var/run/netgate",
								},
							},
						},
					},
					Containers: []v1.Container{
						{
							Name:    "envoy",
							Image:   "envoyproxy/envoy:v1.30-latest",
							Command: []string{"envoy", "-c", "/etc/envoy/envoy.yaml"},
							SecurityContext: &v1.SecurityContext{
								RunAsUser: func(i int64) *int64 { return &i }(0),
							},
							VolumeMounts: []v1.VolumeMount{
								{
									Name:      "netgate-sockets",
									MountPath: "/var/run/netgate",
								},
								{
									Name:      "envoy-config",
									MountPath: "/etc/envoy",
								},
							},
						},
					},
					Volumes: []v1.Volume{
						{
							Name: "netgate-sockets",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: "/var/run/netgate",
									Type: &hostPathType,
								},
							},
						},
						{
							Name: "envoy-config",
							VolumeSource: v1.VolumeSource{
								ConfigMap: &v1.ConfigMapVolumeSource{
									LocalObjectReference: v1.LocalObjectReference{
										Name: "envoy-config",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if err := cluster.ConfigureDaemonSetForRuntimeTestNodepool(ctx, ds); err != nil {
		t.Fatalf("Failed to configure Envoy DaemonSet: %v", err)
	}

	_, err = cluster.CreateDaemonSet(ctx, ds)
	if err != nil {
		t.Fatalf("Failed to create Envoy DaemonSet: %v", err)
	}
	defer cluster.DeleteDaemonSet(ctx, ds)

	defer cluster.DeleteDaemonSet(ctx, ds)

	// 6. Create Client Pod configures with NetGate
	clientImage, err := k8sCtx.ResolveImage(ctx, "alpine")
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}

	podName := fmt.Sprintf("netgate-client-%d", time.Now().UnixNano())
	// We attempt to connect to the dummy IP 1.2.3.4:80.
	// If intercepted, it goes to Envoy -> Echo Service (8080).
	// Echo Service returns the pod hostname.
	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: testcluster.NamespaceDefault,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{
					Name:  "client",
					Image: clientImage,
					Command: []string{
						"/bin/sh", "-c",
						// Wait a bit for Envoy to be ready, then curl.
						// We use 1.2.3.4:80 as target.
						"apk add --no-cache curl && sleep 5 && curl -v --connect-timeout 5 http://1.2.3.4:80",
					},
				},
			},
			Volumes: []v1.Volume{

				{
					Name: "netgate-sockets",
					VolumeSource: v1.VolumeSource{
						HostPath: &v1.HostPathVolumeSource{
							Path: "/var/run/netgate",
							Type: &hostPathType,
						},
					},
				},
			},
			RestartPolicy: v1.RestartPolicyNever,
		},
	}

	pod, err = cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to set pod on cluster %q: %v", cluster.GetName(), err)
	}

	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to create pod on cluster %q: %v", cluster.GetName(), err)
	}
	defer cluster.DeletePod(ctx, pod)

	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		t.Logf("Client Pod logs:\n%s", mustReadLogs(t, ctx, cluster, pod))
		t.Fatalf("Failed to wait for pod on cluster %q: %v", cluster.GetName(), err)
	}

	logs := mustReadLogs(t, ctx, cluster, pod)
	t.Logf("Client Pod Logs:\n%s", logs)

	// Verify header or content
	// netexec returns "hostname: <podname>"
	if !strings.Contains(logs, fmt.Sprintf("hostname: %s", echoPodName)) {
		t.Errorf("Expected logs to contain 'hostname: %s' (evidence of hijacking to echo server), got:\n%s", echoPodName, logs)
	}
}

func mustReadLogs(t *testing.T, ctx context.Context, cluster *testcluster.TestCluster, pod *v1.Pod) string {
	reader, err := cluster.GetLogReader(ctx, pod, v1.PodLogOptions{})
	if err != nil {
		t.Fatalf("Failed to get log reader: %v", err)
	}
	defer reader.Close()
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		t.Fatalf("Failed to read log: %v", err)
	}
	return buf.String()
}

func StrIntOr(i int) intstr.IntOrString {
	return intstr.IntOrString{
		Type:   intstr.Int,
		IntVal: int32(i),
	}
}
