load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def protocolbuffers_protobuf_pull_git_repo():
    git_repository(
        name = "com_google_protobuf",
        remote = "https://github.com/protocolbuffers/protobuf.git",
        commit = "ab840345966d0fa8e7100d771c92a73bfbadd25c",
        shallow_since = "1660065164 +0000",
        #tag = "v21.5",
    )
