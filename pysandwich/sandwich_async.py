import asyncio
import socket

import pysandwich.proto.api.v1.verifiers_pb2 as SandwichVerifiers
from pysandwich.sandwich import Context
from pysandwich.sandwich_protocol import SandwichProtocol

_DEFAULT_LIMIT = 2**16  # 64 KiB


async def open_connection(host=None, port=None, *, limit=_DEFAULT_LIMIT, **kwds):
    """A wrapper for create_connection() returning a (reader, writer) pair.

    The reader returned is a StreamReader instance; the writer is a
    StreamWriter instance.

    The arguments are all the usual arguments to create_connection()
    except protocol_factory; most common are positional host and port,
    with various optional keyword arguments following.

    Additional optional keyword arguments are loop (to set the event loop
    instance to use) and limit (to set the buffer limit passed to the
    StreamReader).

    (If you want to customize the StreamReader and/or
    StreamReaderProtocol classes, just copy the code -- there's
    really nothing special here except some convenience.)
    """
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader(limit=limit, loop=loop)
    protocol = StreamReaderProtocol(reader, loop=loop)
    transport, _ = await loop.create_connection(lambda: protocol, host, port, **kwds)
    writer = StreamWriter(transport, protocol, reader, loop)
    return reader, writer


async def start_server(
    client_connected_cb, host=None, port=None, *, limit=_DEFAULT_LIMIT, **kwds
):
    """Start a socket server, call back for each client connected.

    The first parameter, `client_connected_cb`, takes two parameters:
    client_reader, client_writer.  client_reader is a StreamReader
    object, while client_writer is a StreamWriter object.  This
    parameter can either be a plain callback function or a coroutine;
    if it is a coroutine, it will be automatically converted into a
    Task.

    The rest of the arguments are all the usual arguments to
    loop.create_server() except protocol_factory; most common are
    positional host and port, with various optional keyword arguments
    following.  The return value is the same as loop.create_server().

    Additional optional keyword arguments are loop (to set the event loop
    instance to use) and limit (to set the buffer limit passed to the
    StreamReader).

    The return value is the same as loop.create_server(), i.e. a
    Server object which can be used to stop the service.
    """
    loop = asyncio.get_running_loop()

    def factory():
        reader = asyncio.StreamReader(limit=limit, loop=loop)
        protocol = StreamReaderProtocol(reader, client_connected_cb, loop=loop)
        return protocol

    return await loop.create_server(factory, host, port, **kwds)


if hasattr(socket, "AF_UNIX"):
    # UNIX Domain Sockets are supported on this platform

    async def open_unix_connection(path=None, *, limit=_DEFAULT_LIMIT, **kwds):
        """Similar to `open_connection` but works with UNIX Domain Sockets."""
        loop = asyncio.get_running_loop()

        reader = asyncio.StreamReader(limit=limit, loop=loop)
        protocol = StreamReaderProtocol(reader, loop=loop)
        transport, _ = await loop.create_unix_connection(lambda: protocol, path, **kwds)
        writer = StreamWriter(transport, protocol, reader, loop)
        return reader, writer

    async def start_unix_server(
        client_connected_cb, path=None, *, limit=_DEFAULT_LIMIT, **kwds
    ):
        """Similar to `start_server` but works with UNIX Domain Sockets."""
        loop = asyncio.get_running_loop()

        def factory():
            reader = asyncio.StreamReader(limit=limit, loop=loop)
            protocol = StreamReaderProtocol(reader, client_connected_cb, loop=loop)
            return protocol

        return await loop.create_unix_server(factory, path, **kwds)


class StreamReaderProtocol(
    asyncio.StreamReaderProtocol,
    asyncio.streams.FlowControlMixin,
    asyncio.Protocol,
):
    """Helper class to adapt between Protocol and StreamReader.

    (This is a helper class instead of making StreamReader itself a
    Protocol subclass, because the StreamReader has other potential
    uses, and to prevent the user of the StreamReader to accidentally
    call inappropriate methods of the protocol.)
    """

    def _replace_writer(self, writer):
        transport = writer.transport
        self._stream_writer = writer
        self._transport = transport
        self._over_ssl = True

    def connection_made(self, transport):
        if self._reject_connection:
            context = {
                "message": (
                    "An open stream was garbage collected prior to "
                    "establishing network connection; "
                    'call "stream.close()" explicitly.'
                )
            }
            if self._source_traceback:
                context["source_traceback"] = self._source_traceback
            self._loop.call_exception_handler(context)
            transport.abort()
            return
        self._transport = transport
        reader = self._stream_reader
        if reader is not None:
            reader.set_transport(transport)
        self._over_ssl = transport.get_extra_info("sslcontext") is not None
        if self._client_connected_cb is not None:
            self._stream_writer = StreamWriter(transport, self, reader, self._loop)
            res = self._client_connected_cb(reader, self._stream_writer)
            if asyncio.coroutines.iscoroutine(res):
                self._task = self._loop.create_task(res)
            self._strong_reader = None


class StreamWriter(asyncio.StreamWriter):
    """Wraps a Transport.

    This exposes write(), writelines(), [can_]write_eof(),
    get_extra_info() and close().  It adds drain() which returns an
    optional Future on which you can wait for flow control.  It also
    adds a transport property which references the Transport
    directly.
    """

    async def _sandwich_start_tls(
        self,
        sandwich_context: Context,
        sandwich_verifier: SandwichVerifiers,
        *,
        server_side=False,
        server_hostname=None,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
    ):
        """Upgrade transport to TLS.

        Return a new transport that *protocol* should start using
        immediately.
        """

        if not getattr(self._transport, "_start_tls_compatible", False):
            raise TypeError(
                f"transport {self._transport!r} is not supported by start_tls()"
            )

        waiter = self._loop.create_future()
        ssl_protocol = SandwichProtocol(
            loop=self._loop,
            app_protocol=self._protocol,
            sandwich_context=sandwich_context,
            sandwich_verifier=sandwich_verifier,
            waiter=waiter,
            server_side=server_side,
            server_hostname=server_hostname,
            call_connection_made=False,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout,
        )

        # Pause early so that "ssl_protocol.data_received()" doesn't
        # have a chance to get called before "ssl_protocol.connection_made()".
        self._transport.pause_reading()

        self._transport.set_protocol(ssl_protocol)
        conmade_cb = self._loop.call_soon(ssl_protocol.connection_made, self._transport)
        resume_cb = self._loop.call_soon(self._transport.resume_reading)

        try:
            await waiter
        except BaseException:
            self._transport.close()
            conmade_cb.cancel()
            resume_cb.cancel()
            raise

        return ssl_protocol._app_transport

    async def start_tls(
        self,
        sandwich_context: Context,
        sandwich_verifier: SandwichVerifiers,
        *,
        server_hostname=None,
        ssl_handshake_timeout=None,
        ssl_shutdown_timeout=None,
    ):
        """Upgrade an existing stream-based connection to TLS."""
        server_side = self._protocol._client_connected_cb is not None
        protocol = self._protocol
        await self.drain()

        new_transport = await self._sandwich_start_tls(  # type: ignore
            sandwich_context,
            sandwich_verifier,
            server_side=server_side,
            server_hostname=server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout,
        )
        self._transport = new_transport
        protocol._replace_writer(self)
