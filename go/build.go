package sandwich

// #cgo CFLAGS: -I${SRCDIR}/..
// #cgo LDFLAGS: -L${SRCDIR}/../bazel-bin/c/ -lcontext -ltunnel -lio
import "C"
