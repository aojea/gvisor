load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "netgate",
    srcs = [
        "adapter.go",
        "config.go",
        "netgate.go",
        "proxy_protocol.go",
        "sink_uds.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/transport",
        "//pkg/tcpip/transport/tcp",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "netgate_test",
    srcs = [
    	"netgate_test.go",
    	"proxy_protocol_test.go",
    ],
    library = ":netgate",
    deps = [
        "//pkg/tcpip",
    ],
)
