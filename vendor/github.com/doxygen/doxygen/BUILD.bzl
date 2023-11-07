load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def doxygen_fetch_archive():
    maybe(
        http_archive,
        name = "com_github_doxygen_doxygen",
        url = "https://github.com/doxygen/doxygen/releases/download/Release_1_9_8/doxygen-1.9.8.src.tar.gz",
        sha256 = "05e3d228e8384b5f3af9c8fd6246d22804acb731a3a24ce285c8986ed7e14f62",
        strip_prefix = "doxygen-1.9.8",
        patch_cmds = [
            "sed -i.bak '/testing/d' CMakeLists.txt",
        ],
        build_file = "//vendor/github.com/doxygen/doxygen:BUILD.doxygen.bazel",
    )
