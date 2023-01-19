package sandwich

// #cgo CFLAGS: -I${SRCDIR}/..
// #cgo LDFLAGS: -shared -L${SRCDIR}/../bazel-bin/c/libsandwich_shared.so.runfiles/sandwich/c -lsandwich_shared
import "C"
