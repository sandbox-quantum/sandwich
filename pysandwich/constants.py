import enum

import pysandwich.proto.tunnel_pb2 as SandwichTunnelProto

# After the connection is lost, log warnings after this many write()s.
LOG_THRESHOLD_FOR_CONNLOST_WRITES = 5

# Seconds to wait before retrying accept().
ACCEPT_RETRY_DELAY = 1

# Number of stack entries to capture in debug mode.
# The larger the number, the slower the operation in debug mode
# (see extract_stack() in format_helpers.py).
DEBUG_STACK_DEPTH = 10

# Number of seconds to wait for SSL handshake to complete
# The default timeout matches that of Nginx.
SSL_HANDSHAKE_TIMEOUT = 60.0

# Number of seconds to wait for SSL shutdown to complete
# The default timeout mimics lingering_time
SSL_SHUTDOWN_TIMEOUT = 30.0

# Used in sendfile fallback code.  We use fallback for platforms
# that don't support sendfile, or for TLS connections.
SENDFILE_FALLBACK_READBUFFER_SIZE = 1024 * 256

FLOW_CONTROL_HIGH_WATER_SSL_READ = 256  # KiB
FLOW_CONTROL_HIGH_WATER_SSL_WRITE = 512  # KiB

# Default timeout for joining the threads in the threadpool
THREAD_JOIN_TIMEOUT = 300


# The enum should be here to break circular dependencies between
# base_events and sslproto
class _SendfileMode(enum.Enum):
    UNSUPPORTED = enum.auto()
    TRY_NATIVE = enum.auto()
    FALLBACK = enum.auto()


class AppProtocolState(enum.Enum):
    # This tracks the state of app protocol (https://git.io/fj59P):
    #
    #     INIT -cm-> CON_MADE [-dr*->] [-er-> EOF?] -cl-> CON_LOST
    #
    # * cm: connection_made()
    # * dr: data_received()
    # * er: eof_received()
    # * cl: connection_lost()

    STATE_INIT = "STATE_INIT"
    STATE_CON_MADE = "STATE_CON_MADE"
    STATE_EOF = "STATE_EOF"
    STATE_CON_LOST = "STATE_CON_LOST"


class SandwichTunnelState(enum.Enum):
    NOT_CONNECTED = SandwichTunnelProto.State.STATE_NOT_CONNECTED
    UNWRAPPED = SandwichTunnelProto.State.STATE_CONNECTION_IN_PROGRESS
    DO_HANDSHAKE = SandwichTunnelProto.State.STATE_HANDSHAKE_IN_PROGRESS
    WRAPPED = SandwichTunnelProto.State.STATE_HANDSHAKE_DONE
    FLUSHING = SandwichTunnelProto.State.STATE_BEING_SHUTDOWN
    SHUTDOWN = SandwichTunnelProto.State.STATE_DISCONNECTED
