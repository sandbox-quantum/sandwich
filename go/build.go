package sandwich

// #cgo CFLAGS: -I${SRCDIR}/..
// #cgo LDFLAGS: -L${SRCDIR}/../bazel-bin/sandwich_c/ -lcontext -ltunnel -lio
import "C"
