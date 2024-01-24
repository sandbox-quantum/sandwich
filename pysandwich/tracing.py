# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

"""Sandwich Python Tracing Helpers.

The functions defined here help convert serialized spans from the rust layer
into ReadableSpans that the OpenTelemetry exporter is expecting to get.

Author: th
"""

import logging
import os
from abc import ABC, abstractmethod
from io import BufferedReader

from opentelemetry.proto.trace.v1.trace_pb2 import Span as PB2SPan
from opentelemetry.sdk.trace import Event, ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter
from opentelemetry.trace import SpanContext, Status, StatusCode, TraceFlags
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

logger = logging.getLogger(__name__)


class ByteReader(ABC):
    @abstractmethod
    def read(self, num_bytes: int) -> bytes:
        pass


class ReadableByteArray(bytearray, ByteReader):
    def read(self, num_bytes: int) -> bytes:
        if num_bytes <= 0:
            raise ValueError("Number of bytes to read must be positive")
        if num_bytes > len(self):
            num_bytes = len(self)
        data = self[:num_bytes]
        del self[:num_bytes]
        return bytes(data)


class ByteBufferedReader(BufferedReader, ByteReader):
    def read(self, num_bytes) -> bytes:
        return super().read(num_bytes)


def get_message_length(file: ByteReader) -> int:
    """
    The rust code prepends every protobuf serialized span with the
    size, in bytes, of the span. This gives us a predictable amount of
    data to read from the buffer.
    """
    message_length_bytes = file.read(4)
    if not message_length_bytes:
        return 0

    message_length = int.from_bytes(message_length_bytes, "little")
    return message_length


def convert_pbspan_readable(PBSpan) -> ReadableSpan:
    """
    This converts the opentelemetry protobuf object to
    a readable span, which the span_processor is expecting to get.
    """

    ctx = SpanContext(
        trace_id=int.from_bytes(PBSpan.trace_id, "big"),
        span_id=int.from_bytes(PBSpan.span_id, "big"),
        is_remote=False,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
        trace_state=None,
    )

    events = [
        Event(
            name=str(event.name),
            timestamp=int(event.time_unix_nano),
            attributes=[attribute for attribute in event.attributes],
        )
        for event in PBSpan.events
    ]
    readable_span = ReadableSpan(
        name=str(PBSpan.name),
        context=ctx,
        parent=None,
        attributes=None,
        events=events,
        links=(),
        kind=0,
        instrumentation_info=None,
        status=Status(StatusCode.UNSET),
        start_time=int(PBSpan.start_time_unix_nano),
        end_time=int(PBSpan.end_time_unix_nano),
        instrumentation_scope=None,
    )
    return readable_span


class SandwichTracer:
    def __init__(self, exporter: SpanExporter) -> None:
        self.exporter = exporter
        self.read_buf_fd, self.write_buf_fd = os.pipe()
        os.set_blocking(self.read_buf_fd, False)
        self.read_buf_fd = ByteBufferedReader(
            os.fdopen(self.read_buf_fd, mode="rb"), buffer_size=10485760
        )

        self._carrier = {}
        TraceContextTextMapPropagator().inject(self._carrier)
        self.context_string = self._carrier.get("traceparent", "")

    def export_span_buffer(self):
        while True:
            message_length = get_message_length(self.read_buf_fd)
            if not message_length:
                break
            deserialized_span = PB2SPan()
            span_bytes = self.read_buf_fd.read(message_length)
            deserialized_span.ParseFromString(span_bytes)

            self.exporter.export([convert_pbspan_readable(deserialized_span)])
