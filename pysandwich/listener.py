# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import ctypes

import pysandwich.proto.api.v1.listener_configuration_pb2 as ListenerAPI
import pysandwich.proto.io_pb2 as SandwichIOProto
from pysandwich import sandwich
from pysandwich.io import IOException, OwnedIO
from pysandwich.io_helpers import SwOwnedIOWrapper

"""Sandwich Listener API.

This API creates listener objects which can be used by servers
to establish multiple connections.

Author: jgoertzen-sb
"""


class Listener:
    """Listener provides listen and accept functions to spawn new Sandwich Owned IO"""

    def __init__(
        self,
        configuration: ListenerAPI.ListenerConfiguration,
    ):
        self._configuration = configuration
        self._serialized_conf = self._configuration.SerializeToString()
        self._listener = ctypes.c_void_p(None)
        self._sandwich_clib = sandwich.sandwich()
        err = self._sandwich_clib.c_call(
            "sandwich_listener_new",
            self._serialized_conf,
            len(self._serialized_conf),
            ctypes.byref(self._listener),
        )
        if err is not None:
            excp = sandwich._error_code_to_exception(err)
            self._sandwich_clib.c_call("sandwich_error_free", err)
            raise excp

    def listen(self):
        err = self._sandwich_clib.c_call("sandwich_listener_listen", self._listener)
        if err != SandwichIOProto.IOERROR_OK:
            raise IOException(err.value)

    def accept(self) -> SwOwnedIOWrapper:
        owned_ptr = ctypes.POINTER(OwnedIO)()
        err = self._sandwich_clib.c_call(
            "sandwich_listener_accept",
            self._listener,
            ctypes.byref(owned_ptr),
        )
        if err != SandwichIOProto.IOERROR_OK:
            raise IOException(err)
        return SwOwnedIOWrapper(owned_ptr.contents)

    def close(self):
        self._sandwich_clib.c_call("sandwich_listener_close", self._listener)

    def __del__(self):
        self._sandwich_clib.c_call("sandwich_listener_free", self._listener)
