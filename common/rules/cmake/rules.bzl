def cmake_processor_flags():
    """Returns the -DCMAKE_SYSTEM_NAME and -DCMAKE_SYSTEM_PROCESSOR, depending
    on the platform OS and platform architecture.

    Outputs:
      Array of CMake flags.
    """
    return select({
        "@platforms//os:ios": [
            "-DCMAKE_SYSTEM_NAME=Darwin",
        ],
        "@platforms//os:macos": [
            "-DCMAKE_SYSTEM_NAME=Darwin",
        ],
        "@platforms//os:linux": [
            "-DCMAKE_SYSTEM_NAME=Linux",
        ],
        "//conditions:default": [],
    }) + select({
        "@platforms//cpu:arm": [
            "-DCMAKE_SYSTEM_PROCESSOR=arm",
        ],
        "@platforms//cpu:arm64": [
            "-DCMAKE_SYSTEM_PROCESSOR=arm64",
        ],
        "@platforms//cpu:i386": [
            "-DCMAKE_SYSTEM_PROCESSOR=x86",
        ],
        "@platforms//cpu:x86_64": [
            "-DCMAKE_SYSTEM_PROCESSOR=x86_64",
        ],
        "//conditions:default": [],
    })
