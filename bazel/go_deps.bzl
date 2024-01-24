load("//common/build/go:deps.bzl", "go_deps")

# gazelle:repository_macro common/build/go/deps.bzl%go_deps
def sandwich_go_deps():
    go_deps()
