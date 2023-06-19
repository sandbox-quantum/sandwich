import asyncio
import collections
import warnings
from asyncio.log import logger
from collections.abc import Iterable
from ssl import MemoryBIO
from typing import Any

import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
import pysandwich.constants as constants
import pysandwich.errors as errors
import pysandwich.io as SandwichIO
from pysandwich.constants import AppProtocolState, SandwichTunnelState
from pysandwich.sandwich import Context, Tunnel


class _SandwichProtocolTransport(
    asyncio.transports._FlowControlMixin, asyncio.Transport
):
    _start_tls_compatible = True
    _sendfile_compatible = constants._SendfileMode.FALLBACK

    def __init__(
        self, loop: asyncio.AbstractEventLoop, ssl_protocol: asyncio.Protocol
    ) -> None:
        self._loop = loop
        self._ssl_protocol = ssl_protocol
        self._closed = False

    # Base Transport

    def close(self) -> None:
        """Close the transport.

        Buffered data will be flushed asynchronously.  No more data
        will be received.  After all buffered data is flushed, the
        protocol's connection_lost() method will (eventually) called
        with None as its argument.
        """
        if not self._closed:
            self._closed = True
            self._ssl_protocol._start_shutdown()
        else:
            self._ssl_protocol = None

    def __del__(self, _warnings=warnings):
        if not self._closed:
            self._closed = True
            _warnings.warn(
                "unclosed transport <_SandwichProtocolTransport " "object>",
                ResourceWarning,
            )

    def is_closing(self) -> bool:
        # Check if the protocol is in shutdown state
        return self._closed

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        # Return true in self._over_ssl
        return True

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        self._ssl_protocol._set_app_protocol(protocol)

    def get_protocol(self) -> asyncio.BaseProtocol:
        return self._ssl_protocol._app_protocol

    # End Base Transport

    # Read-only Transport

    def is_reading(self) -> bool:
        return not self._ssl_protocol._app_reading_paused

    def pause_reading(self) -> None:
        """Pause the receiving end.

        No data will be passed to the protocol's data_received()
        method until resume_reading() is called.
        """
        self._ssl_protocol._pause_reading()

    def resume_reading(self) -> None:
        """Resume the receiving end.

        Data received will once again be passed to the protocol's
        data_received() method.
        """
        self._ssl_protocol._resume_reading()

    # End Read-only Transport

    # Write-only Transport

    def abort(self) -> None:
        """Close the transport immediately.

        Buffered data will be lost.  No more data will be received.
        The protocol's connection_lost() method will (eventually) be
        called with None as its argument.
        """
        self._closed = True
        if self._ssl_protocol is not None:
            self._ssl_protocol._abort()

    def can_write_eof(self) -> bool:
        return False

    def get_write_buffer_limits(self) -> tuple[int, int]:
        return (
            self._ssl_protocol._outgoing_low_water,
            self._ssl_protocol._outgoing_high_water,
        )

    def get_write_buffer_size(self) -> int:
        """Return the current size of the write buffers."""
        return self._ssl_protocol._get_write_buffer_size()

    def set_write_buffer_limits(
        self, high: int | None = None, low: int | None = None
    ) -> None:
        """Set the high- and low-water limits for write flow control.

        These two values control when to call the protocol's
        pause_writing() and resume_writing() methods.  If specified,
        the low-water limit must be less than or equal to the
        high-water limit.  Neither value can be negative.

        The defaults are implementation-specific.  If only the
        high-water limit is given, the low-water limit defaults to an
        implementation-specific value less than or equal to the
        high-water limit.  Setting high to zero forces low to zero as
        well, and causes pause_writing() to be called whenever the
        buffer becomes non-empty.  Setting low to zero causes
        resume_writing() to be called only once the buffer is empty.
        Use of zero for either limit is generally sub-optimal as it
        reduces opportunities for doing I/O and computation
        concurrently.
        """
        self._ssl_protocol._set_write_buffer_limits(high, low)
        self._ssl_protocol._control_app_writing()

    def write(self, data: bytes | bytearray | memoryview) -> None:
        """Write some data bytes to the transport.

        This does not block; it buffers the data and arranges for it
        to be sent out asynchronously.
        """
        if not data:
            return
        self._ssl_protocol._write_appdata((data,))

    def writelines(
        self, list_of_data: Iterable[bytes | bytearray | memoryview]
    ) -> None:
        """Write a list (or any iterable) of data bytes to the transport.

        The default implementation concatenates the arguments and
        calls write() on the result.
        """
        self._ssl_protocol._write_appdata(list_of_data)

    def write_eof(self) -> None:
        """Close the write end after flushing buffered data.

        This raises :exc:`NotImplementedError` right now.
        """
        raise NotImplementedError

    # End Write-only Transport

    def set_read_buffer_limits(self, high=None, low=None) -> None:
        """Set the high- and low-water limits for read flow control.

        These two values control when to call the upstream transport's
        pause_reading() and resume_reading() methods.  If specified,
        the low-water limit must be less than or equal to the
        high-water limit.  Neither value can be negative.

        The defaults are implementation-specific.  If only the
        high-water limit is given, the low-water limit defaults to an
        implementation-specific value less than or equal to the
        high-water limit.  Setting high to zero forces low to zero as
        well, and causes pause_reading() to be called whenever the
        buffer becomes non-empty.  Setting low to zero causes
        resume_reading() to be called only once the buffer is empty.
        Use of zero for either limit is generally sub-optimal as it
        reduces opportunities for doing I/O and computation
        concurrently.
        """
        self._ssl_protocol._set_read_buffer_limits(high, low)
        self._ssl_protocol._control_ssl_reading()

    def get_read_buffer_limits(self) -> tuple[int, int]:
        return (
            self._ssl_protocol._incoming_low_water,
            self._ssl_protocol._incoming_high_water,
        )

    def get_read_buffer_size(self) -> int:
        """Return the current size of the read buffer."""
        return self._ssl_protocol._get_read_buffer_size()

    # Force Close

    def _force_close(self, exc):
        self._closed = True
        self._ssl_protocol._abort(exc)

    @property
    def _protocol_paused(self):
        # Required for sendfile fallback pause_writing/resume_writing logic
        return self._ssl_protocol._app_writing_paused


def add_flowcontrol_defaults(high, low, kb):
    """Set default high = 4 \times low"""
    if high is None:
        if low is None:
            hi = kb * 1024
        else:
            lo = low
            hi = 4 * lo
    else:
        hi = high
    if low is None:
        lo = hi // 4
    else:
        lo = low

    if not hi >= lo >= 0:
        raise ValueError("high (%r) must be >= low (%r) must be >= 0" % (hi, lo))

    return hi, lo


class SandwichMemory(SandwichIO.IO):
    def __init__(self, incoming: MemoryBIO, outgoing: MemoryBIO) -> None:
        self.incoming = incoming
        self.outgoing = outgoing

    def read(self, n: int, tunnel_state) -> bytearray:
        try:
            return self.incoming.read(n)
        except Exception as exc:
            # TODO: try to catch detail exc here
            raise exc

    def write(self, buf: bytearray | memoryview, tunnel_state) -> int:
        try:
            return self.outgoing.write(buf)
        except Exception as exc:
            # TODO: try to catch detail exc here
            raise exc

    def close(self):
        self.incoming.write_eof()
        self.outgoing.write_eof()
        pass


class SandwichProtocol(asyncio.BufferedProtocol):
    # Default the buffer is 256 Kb
    max_size = 256 * 1024

    _handshake_start_time = None
    _handshake_timeout_handle = None
    _shutdown_timeout_handle = None

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        app_protocol: asyncio.WriteTransport,
        sandwich_context: Context,
        sandwich_verifier: SandwichVerifiers,
        waiter: asyncio.Future,
        server_side=None,
        server_hostname=None,
        call_connection_made=True,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
    ) -> None:
        # Asyncio Loop
        self._loop = loop

        # Waiter
        self._waiter = waiter

        # Base Transport: Application Protocol
        self._app_protocol = None
        self._app_protocol_is_buffer = False
        self._set_app_protocol(app_protocol)

        # Read-only Transport: Buffered Protocol
        self._app_reading_paused = False
        self._incoming_low_water = 0
        self._incoming_high_water = 0
        self._set_read_buffer_limits()
        self._ssl_incoming = MemoryBIO()
        self._ssl_reading_paused = False

        # Write-only Transport: Buffered Protocol
        self._outgoing_low_water = 0
        self._outgoing_high_water = 0
        self._set_write_buffer_limits()
        self._app_writing_paused = False
        self._ssl_outgoing = MemoryBIO()
        self._transport = None
        self._ssl_writing_paused = False

        # Write-only Transport: Application Transport
        self._app_transport = None
        self._app_transport_created = False
        self._get_app_transport()

        # Write-only Transport: Write backlog
        self._write_backlog = collections.deque()
        self._write_buffer_size = 0

        # End Transport Class

        # SandwichSSLProtocol

        # Timeout for Handshake and Shutdown
        # Set shutdown timeout same as NGINX
        if ssl_shutdown_timeout is None:
            ssl_shutdown_timeout = constants.SSL_SHUTDOWN_TIMEOUT
            # ssl_shutdown_timeout = 1

        elif ssl_shutdown_timeout <= 0:
            raise ValueError(
                f"ssl_shutdown_timeout should be a positive number, "
                f"got {ssl_shutdown_timeout}"
            )
        self._ssl_shutdown_timeout = ssl_shutdown_timeout

        # Set handshake timeout to same as NGINX
        if ssl_handshake_timeout is None:
            ssl_handshake_timeout = constants.SSL_HANDSHAKE_TIMEOUT
        elif ssl_handshake_timeout <= 0:
            raise ValueError(
                f"ssl_handshake_timeout should be a positive number, "
                f"got {ssl_handshake_timeout}"
            )
        self._ssl_handshake_timeout = ssl_handshake_timeout

        # EOF Marker
        self._eof_received = False

        # Sandwich configuration
        if sandwich_context is None:
            raise ValueError("Sandwich Context is None")
        if sandwich_verifier is None:
            raise ValueError("Sandwcih Verifier is None")
        self._sandwich_context = sandwich_context
        self._sandwich_verifier = sandwich_verifier
        self._sandwich_io = SandwichMemory(
            self._ssl_incoming,
            self._ssl_outgoing,
        )
        self._tunnel = None
        self._sock = None

        # Place holder for optional server_side and server_hostname
        self._server_side = server_side
        if server_hostname and not server_side:
            self._server_hostname = server_hostname
        else:
            self._server_hostname = None

        # Memory buffer for SSL
        self._ssl_buffer = bytearray(self.max_size)
        self._ssl_buffer_view = memoryview(self._ssl_buffer)

        # State of Control Plane and Data Plane
        self._state = SandwichTunnelState.UNWRAPPED
        if call_connection_made:
            self._app_state = AppProtocolState.STATE_INIT
        else:
            self._app_state = AppProtocolState.STATE_CON_MADE

        # Statistic of connection
        self._conn_lost = 0

    """Transport Implementation"""

    # Base Transport
    def _set_app_protocol(self, app_protocol) -> None:
        self._app_protocol = app_protocol
        # Make fast hasattr check first
        if hasattr(app_protocol, "get_buffer") and isinstance(
            app_protocol, asyncio.BufferedProtocol
        ):
            self._app_protocol_is_buffer = True
        else:
            self._app_protocol_is_buffer = False

    def _start_shutdown(self) -> None:
        """Shutdown flow with timeout"""
        if self._state in (
            SandwichTunnelState.FLUSHING,
            SandwichTunnelState.SHUTDOWN,
            SandwichTunnelState.UNWRAPPED,
        ):
            return
        if self._app_transport is not None:
            self._app_transport._closed = True

        match self._state:
            case SandwichTunnelState.DO_HANDSHAKE:
                self._abort()
            case _:
                self._set_state(SandwichTunnelState.FLUSHING)
                self._shutdown_timeout_handle = self._loop.call_later(
                    self._ssl_shutdown_timeout, lambda: self._check_shutdown_timeout()
                )
                self._do_flush()

    # Timer for _start_shutdown()

    def _check_shutdown_timeout(self) -> None:
        if self._state in (SandwichTunnelState.FLUSHING, SandwichTunnelState.SHUTDOWN):
            self._transport._force_close(TimeoutError("SSL shutdown timed out"))

    # Read-only transport
    def _pause_reading(self) -> None:
        self._app_reading_paused = True

    def _resume_reading(self) -> None:
        if self._app_reading_paused:
            self._app_reading_paused = False

            def resume():
                if self._state == SandwichTunnelState.WRAPPED:
                    self._do_read()
                elif self._state == SandwichTunnelState.FLUSHING:
                    self._do_flush()
                elif self._state == SandwichTunnelState.SHUTDOWN:
                    self._do_shutdown()

            self._loop.call_soon(resume)

    # Write-only transport

    def _abort(self, exc: Exception | None) -> None:
        self._set_state(SandwichTunnelState.UNWRAPPED)
        if self._transport is not None:
            self._transport.abort()

    def _control_app_writing(self) -> None:
        size = self._get_write_buffer_size()
        if size >= self._outgoing_high_water and not self._app_writing_paused:
            self._app_writing_paused = True
            try:
                self._app_protocol.pause_writing()
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:
                self._loop.call_exception_handler(
                    {
                        "message": "protocol.pause_writing() failed",
                        "exception": exc,
                        "transport": self._app_transport,
                        "protocol": self,
                    }
                )
        elif size <= self._outgoing_low_water and self._app_writing_paused:
            self._app_writing_paused = False
            try:
                self._app_protocol.resume_writing()
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException as exc:
                self._loop.call_exception_handler(
                    {
                        "message": "protocol.resume_writing() failed",
                        "exception": exc,
                        "transport": self._app_transport,
                        "protocol": self,
                    }
                )

    def _get_write_buffer_size(self) -> int:
        return self._ssl_outgoing.pending + self._write_buffer_size

    def _set_write_buffer_limits(self, high=None, low=None) -> None:
        high, low = add_flowcontrol_defaults(
            high, low, constants.FLOW_CONTROL_HIGH_WATER_SSL_WRITE
        )
        self._outgoing_high_water = high
        self._outgoing_low_water = low

    def _write_appdata(
        self, list_of_data: Iterable[bytes | bytearray | memoryview]
    ) -> None:
        if self._state in (
            SandwichTunnelState.FLUSHING,
            SandwichTunnelState.SHUTDOWN,
            SandwichTunnelState.UNWRAPPED,
        ):
            if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
                logger.warning("SSL connection is closed")
            self._conn_lost += 1
            return

        self._write_backlog.extend(list_of_data)
        self._write_buffer_size += sum(len(data) for data in list_of_data)

        try:
            if self._state == SandwichTunnelState.WRAPPED:
                self._do_write()

        except Exception as ex:
            self._fatal_error(ex, "Fatal error on SSL protocol")

    # Additional functions for Read-only Transport
    def _set_read_buffer_limits(
        self, high: int | None = None, low: int | None = None
    ) -> None:
        high, low = add_flowcontrol_defaults(
            high, low, constants.FLOW_CONTROL_HIGH_WATER_SSL_READ
        )
        self._incoming_high_water = high
        self._incoming_low_water = low

    def _control_ssl_reading(self) -> None:
        size = self._get_read_buffer_size()
        if size >= self._incoming_high_water and not self._ssl_reading_paused:
            self._ssl_reading_paused = True
            self._transport.pause_reading()
        elif size <= self._incoming_low_water and self._ssl_reading_paused:
            self._ssl_reading_paused = False
            self._transport.resume_reading()

    def _get_read_buffer_size(self) -> int:
        return self._ssl_incoming.pending

    # End functions serve Transport Class

    # Helpers for __init__
    def _get_app_transport(self):
        if self._app_transport is None:
            if self._app_transport_created:
                raise RuntimeError("Creating _SandwichProtocolTransport twice")
            self._app_transport = _SandwichProtocolTransport(self._loop, self)
            self._app_transport_created = True
        return self._app_transport

    """Protocol Implementation"""

    # Base Protocol

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Perform SSL handshake when connection is made

        When handshake success, update transport state and tunnel state
        """

        self._transport = transport
        self._tunnel = Tunnel(
            self._sandwich_context,
            self._sandwich_io,
            self._sandwich_verifier,
        )

        if self._tunnel is None:
            raise ImportError("Couldn't build tunnel")
        # When the handshake is completed, Tunnel must release the socket
        # Timeout Handshake() start
        self._start_handshake()

    def _on_handshake_complete(self, handshake_exc: Exception | None) -> None:
        """Called when handshake is completed or raise exception"""

        if self._handshake_timeout_handle is not None:
            self._handshake_timeout_handle.cancel()
            self._handshake_timeout_handle = None

        try:
            if handshake_exc is None:
                self._set_state(SandwichTunnelState.WRAPPED)
            else:
                raise handshake_exc
        except Exception as exc:
            # Failed to _set_state or _tunnel.set_io
            self._set_state(SandwichTunnelState.UNWRAPPED)
            msg = "SSL handshake failed"
            self._fatal_error(exc, msg)
            self._wakeup_waiter(exc)
            return

        if self._loop.get_debug():
            dt = self._loop.time() - self._handshake_start_time
            logger.debug("%r: SSL handshake took %.1f ms", self, dt * 1e3)

        # From now on we check condition of AppProtocolState to Read/Write
        if self._app_state == AppProtocolState.STATE_INIT:
            # This will move our custom SSL protocol to replace current transport
            self._app_state = AppProtocolState.STATE_CON_MADE
            self._app_protocol.connection_made(self._get_app_transport())
        self._wakeup_waiter()
        self._do_read()

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when the low-level connection is lost or closed.

        The argument is an exception object or None (the latter
        meaning a regular EOF is received or the connection was
        aborted or closed).
        """
        # Clear backlog buffer
        self._write_backlog.clear()
        # Clear outgoing memory, because the connection has lost anyway
        self._ssl_outgoing.read()
        self._conn_lost += 1

        # Just mark the app transport as closed so that its __dealloc__
        # doesn't complain.
        if self._app_transport is not None:
            self._app_transport._closed = True

        if self._state != SandwichTunnelState.DO_HANDSHAKE:
            if self._app_state in (
                AppProtocolState.STATE_CON_MADE,
                AppProtocolState.STATE_EOF,
            ):
                self._set_app_state(AppProtocolState.STATE_CON_LOST)
                self._loop.call_soon(self._app_protocol.connection_lost, exc)

        if self._state != SandwichTunnelState.SHUTDOWN:
            self._set_state(SandwichTunnelState.UNWRAPPED)
        self._transport = None
        self._app_transport = None
        self._app_protocol = None
        self._wakeup_waiter(exc)

        if self._shutdown_timeout_handle:
            self._shutdown_timeout_handle.cancel()
            self._shutdown_timeout_handle = None
        if self._handshake_timeout_handle:
            self._handshake_timeout_handle.cancel()
            self._handshake_timeout_handle = None

    def pause_writing(self) -> None:
        assert not self._ssl_writing_paused
        self._ssl_writing_paused = True

    def resume_writing(self) -> None:
        assert self._ssl_writing_paused
        self._ssl_writing_paused = False
        self._process_outgoing()

    def _process_outgoing(self) -> int:
        if not self._ssl_writing_paused:
            data = self._ssl_outgoing.read()
            if len(data):
                self._transport.write(data)
        self._control_app_writing()
        return len(data)

    # End Base Protocol

    # Buffered Protocol
    def get_buffer(self, n) -> memoryview:
        want = n
        if want <= 0 or want > self.max_size:
            want = self.max_size
        if len(self._ssl_buffer) < want:
            self._ssl_buffer = bytearray(want)
            self._ssl_buffer_view = memoryview(self._ssl_buffer)
        return self._ssl_buffer_view

    def buffer_updated(self, nbytes) -> None:
        self._ssl_incoming.write(self._ssl_buffer_view[:nbytes])

        match self._state:
            case SandwichTunnelState.DO_HANDSHAKE:
                self._do_handshake()

            case SandwichTunnelState.WRAPPED:
                self._do_read()

            case SandwichTunnelState.FLUSHING:
                self._do_flush()

            case SandwichTunnelState.SHUTDOWN:
                self._do_shutdown()

    # EOF_Received can be shared with Streaming Protocol

    def eof_received(self) -> bool | None:
        """Called when the other end of the low-level stream
        is half-closed.

        If this returns a false value (including None), the transport
        will close itself.  If it returns a true value, closing the
        transport is up to the protocol.
        """
        self._eof_received = True
        try:
            if self._loop.get_debug():
                logger.debug("%r received EOF", self)

            match self._state:
                case SandwichTunnelState.DO_HANDSHAKE:
                    self._on_handshake_complete(ConnectionResetError)

                case SandwichTunnelState.WRAPPED:
                    self._set_state(SandwichTunnelState.FLUSHING)
                    if self._app_reading_paused:
                        return True
                    else:
                        self._do_flush()

                case SandwichTunnelState.FLUSHING:
                    self._do_write()
                    self._set_state(SandwichTunnelState.SHUTDOWN)
                    self._do_shutdown()

                case SandwichTunnelState.SHUTDOWN:
                    self._do_shutdown()

        except Exception:
            self._transport.close()
            raise

    # End Buffered Protocol

    def _do_read(self) -> None:
        """Move all backlog to incoming memory and
        move all from outgoing memory to trasport"""
        # self._write_backlog_to_incoming_memory()
        # self._read_from_outgoing_memory()
        if self._state not in (
            SandwichTunnelState.WRAPPED,
            SandwichTunnelState.FLUSHING,
        ):
            return

        try:
            if not self._app_reading_paused:
                if self._app_protocol_is_buffer:
                    # Read for Buffered Protocol
                    self._do_read__buffered()
                else:
                    # Read for Stream Protocol
                    self._do_read_stream()
                if self._write_backlog:
                    self._do_write()
                else:
                    self._process_outgoing()
            self._control_ssl_reading()
        except Exception as ex:
            self._fatal_error(ex, "Fatal error on SSL protocol")

    def _do_read__buffered(self) -> None:
        """Read data from ssl_incoming to the buffer"""

        offset = 0
        count = 1

        buf = self.get_buffer(self._get_read_buffer_size())
        wants = len(buf)

        try:
            data = self._tunnel.read(wants)
            count = len(data)
            buf[:count] = data

            if count > 0:
                offset = count
                while offset < wants:
                    data = self._tunnel.read(wants - offset)
                    count = len(data)
                    buf[offset : offset + count] = data
                    if count > 0:
                        offset += count
                    else:
                        break
                else:
                    self._loop.call_soon(lambda: self._do_read())
        except Exception as exc:
            raise exc

        if offset > 0:
            self.buffer_updated(offset)
        if not count:
            # close_notify
            self._call_eof_received()
            self._start_shutdown()

    def _do_read_stream(self) -> None:
        """Read all data from ssl_incoming memory to outgoing plaintext"""
        chunk = b"1"
        try:
            while want := min(self._get_read_buffer_size(), self.max_size):
                chunk = self._tunnel.read(want)
                if chunk:
                    # If there is data, write to outgoing plaintext
                    self._app_protocol.data_received(chunk)

            if not chunk:
                # SSL close_notify:
                # https://www.openssl.org/docs/manmaster/man3/SSL_shutdown.html
                self._call_eof_received()
                self._start_shutdown()

        except errors.RecordPlaneClosedException:
            pass

    def _do_write(self) -> None:
        try:
            while self._write_backlog:
                data = self._write_backlog.popleft()
                count = self._tunnel.write(data)
                data_len = len(data)
                if count < data_len:
                    self._write_backlog.appendleft(data[count:])
                    self._write_buffer_size -= count
                else:
                    # This is almost always the case
                    self._write_buffer_size -= data_len
        except Exception as exc:
            raise exc
        self._process_outgoing()

    def _call_eof_received(self) -> None:
        try:
            if self._app_state == AppProtocolState.STATE_CON_MADE:
                self._app_state = AppProtocolState.STATE_EOF
                keep_open = self._app_protocol.eof_received()
                if keep_open:
                    logger.warning(
                        "returning true from eof_received() "
                        "has no effect when using ssl"
                    )
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as ex:
            self._fatal_error(ex, "Error calling eof_received()")

    def _do_flush(self) -> None:
        """Flush all data in backlog"""
        self._do_read()
        self._set_state(SandwichTunnelState.SHUTDOWN)
        self._do_shutdown()

    def _do_shutdown(self) -> None:
        """Close Tunnel and also its memory IO"""
        try:
            if not self._eof_received:
                self._tunnel.close()
            self._process_outgoing()
        except Exception as exc:
            self._on_shutdown_complete(exc)
        else:
            self._process_outgoing()
            self._call_eof_received()
            self._on_shutdown_complete(None)

    def _on_shutdown_complete(self, shutdown_exc: Exception | None) -> None:
        """Called when the shutdown is completed or received exception"""
        if self._shutdown_timeout_handle is not None:
            self._shutdown_timeout_handle.cancel()
            self._shutdown_timeout_handle = None

        if shutdown_exc:
            self._fatal_error(shutdown_exc)
        else:
            # Close Transport socket
            self._loop.call_soon(self._transport.close)

    # Helpers for `connection_made()` SSL Handshake
    def _start_handshake(self) -> None:
        """Start handshake flow with timeout"""
        if self._loop.get_debug():
            logger.debug("%r starts SSL handshake", self)
            self._handshake_start_time = self._loop.time()
        else:
            self._handshake_start_time = None

        self._set_state(SandwichTunnelState.DO_HANDSHAKE)

        # start handshake timeout count down
        self._handshake_timeout_handle = self._loop.call_later(
            self._ssl_handshake_timeout, lambda: self._check_handshake_timeout()
        )

        self._do_handshake()

    def _do_handshake(self) -> None:
        """Perform TLS handshake"""
        try:
            # Write handshake data to ssl_outgoing
            self._tunnel.handshake()
        except errors.HandshakeError:
            # Push data from ssl_outgoing to outgoing transport
            self._process_outgoing()
        except Exception as exc:
            self._on_handshake_complete(exc)
        else:
            self._on_handshake_complete(None)

    # Helper for _start_handshake
    def _check_handshake_timeout(self) -> None:
        if self._state == SandwichTunnelState.DO_HANDSHAKE:
            msg = (
                f"SSL handshake is taking longer than "
                f"{self._ssl_handshake_timeout} seconds: "
                f"aborting the connection"
            )
            self._fatal_error(ConnectionAbortedError(msg))

    def _wakeup_waiter(self, exc=None):
        if self._waiter is None:
            return
        if not self._waiter.cancelled():
            if exc is not None:
                self._waiter.set_exception(exc)
            else:
                self._waiter.set_result(None)
        self._waiter = None

    def _set_state(self, new_state: SandwichTunnelState):
        allowed = False

        if self._state == new_state:
            return

        match (self._state, new_state):
            case (_, SandwichTunnelState.NOT_CONNECTED):
                # Initialize state
                allowed = True
            case (SandwichTunnelState.NOT_CONNECTED, SandwichTunnelState.UNWRAPPED):
                # Have connection
                allowed = True
            case (SandwichTunnelState.UNWRAPPED, SandwichTunnelState.DO_HANDSHAKE):
                # Start handshake
                allowed = True
            case (SandwichTunnelState.DO_HANDSHAKE, SandwichTunnelState.WRAPPED):
                # Handhshake success
                allowed = True
            case (SandwichTunnelState.DO_HANDSHAKE, SandwichTunnelState.UNWRAPPED):
                # When handshake fail
                allowed = True
            case (SandwichTunnelState.WRAPPED, SandwichTunnelState.FLUSHING):
                # Receive EOF
                allowed = True
            case (SandwichTunnelState.WRAPPED, SandwichTunnelState.UNWRAPPED):
                # When connection is lost, must restart handshake
                allowed = True
            case (SandwichTunnelState.FLUSHING, SandwichTunnelState.SHUTDOWN):
                # Receive shutdown
                allowed = True

        if allowed:
            self._state = new_state

        else:
            raise RuntimeError(
                "cannot switch state from {} to {}".format(self._state, new_state)
            )

    def _set_app_state(self, new_state: AppProtocolState):
        allowed = False

        if self._app_state == new_state:
            return

        match (self._app_state, new_state):
            case (_, AppProtocolState.STATE_INIT):
                allowed = True
            case (AppProtocolState.STATE_INIT, AppProtocolState.STATE_CON_MADE):
                allowed = True
            case (AppProtocolState.STATE_CON_MADE, AppProtocolState.STATE_INIT):
                # When connection is lost
                allowed = True
            case (AppProtocolState.STATE_CON_MADE, AppProtocolState.STATE_CON_LOST):
                # When connection is lost
                allowed = True
            case (AppProtocolState.STATE_CON_MADE, AppProtocolState.STATE_EOF):
                allowed = True
            case (AppProtocolState.STATE_EOF, AppProtocolState.STATE_CON_LOST):
                allowed = True

        if allowed is True:
            self._app_state = new_state

        else:
            raise RuntimeError(
                f"cannot switch tunnel state from {self._app_state} to {new_state}"
            )

    def _fatal_error(self, exc, message="Fatal error on transport"):
        if isinstance(exc, OSError):
            if self._loop.get_debug():
                logger.debug("%r: %s", self, message, exc_info=True)
        elif not isinstance(exc, asyncio.CancelledError):
            self._loop.call_exception_handler(
                {
                    "message": message,
                    "exception": exc,
                    "transport": self._transport,
                    "protocol": self,
                }
            )

    def _actually_state(self):
        return self._tunnel.state(), self._state

    # End
