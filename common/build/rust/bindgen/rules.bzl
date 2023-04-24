def bindgen_add_prefix_link_name(prefix):
    """Returns the list of arguments necessary to apply a prefix to the link names
    of symbols.

    This function returns a list of two elements. The first one is the
    `--prefix-link-name` option, which tells bindgen to apply a prefix to the
    link names of symbols when building the .rs files.
    The second is the chosen prefix.

    On some operating systems such as macOS or iOS, symbols are always internally
    prefixed with a `_`. It means that when we compile an object that contains
    the definition of `function`, its link name will actually be `_function`.

    This function takes care of that divergence, by applying this leading `_` when
    it is necessary.

    Arguments:
      prefix:
        The prefix to modify if necessary.

    Returns:
      A list of arguments to add to the `bindgen_flags` argument of rule
      `rust_bindgen_library`.
    """
    return ["--prefix-link-name"] + select({
        "@platforms//os:ios": ["_{}".format(prefix)],
        "@platforms//os:macos": ["_{}".format(prefix)],
        "@platforms//os:tvos": ["_{}".format(prefix)],
        "@platforms//os:watchos": ["_{}".format(prefix)],
        "//conditions:default": ["{}".format(prefix)],
    })
