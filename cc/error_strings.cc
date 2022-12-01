///
/// \file
/// \brief Error strings API implementation.
///
/// \author thb-sb

#include "cc/error_strings.h"

namespace saq::sandwich {

auto GetStringError(const enum Error err) -> std::string_view {
  switch (err) {
    case Error::kOk: {
      return "no error";
    }
    case Error::kInvalidArgument: {
      return "invalid argument";
    }
    case Error::kMemory: {
      return "memory error";
    }
    case Error::kIo: {
      return "I/O error";
    }
    case Error::kUnknown: {
      return "unknown error";
    }
    case Error::kInvalidConfiguration: {
      return "invalid configuration";
    }
    case Error::kUnsupportedImplementation: {
      return "unsupported implementation";
    }
    case Error::kUnsupportedProtocol: {
      return "unsupported protocol";
    }
    case Error::kImplementationProtocolMismatch: {
      return "implementation and protocol mismatch";
    }
    case Error::kProtobuf: {
      return "protobuf error";
    }
    case Error::kNetworkInvalidAddress: {
      return "invalid network address";
    }
    case Error::kNetworkInvalidPort: {
      return "invalid network port";
    }
    case Error::kInvalidContext: {
      return "invalid context";
    }
    case Error::kBadFd: {
      return "bad file descriptor";
    }
    case Error::kUnsupportedTunnelMethod: {
      return "unsupported tunnel method";
    }
    case Error::kIntegerOverflow: {
      return "integer overflow";
    }
    case Error::kMemoryOverflow: {
      return "memory overflow";
    }
    case Error::kImplementation: {
      return "implementation error";
    }
    case Error::kInvalidTunnel: {
      return "invalid tunnel";
    }
    case Error::kInvalidKem: {
      return "invalid KEM";
    }
    case Error::kTimeout: {
      return "timeout reached";
    }
    case Error::kNetworkAddressResolve: {
      return "failed to resolve network address";
    }
    case Error::kNetworkConnect: {
      return "failed to connect";
    }
    case Error::kSocketFailed: {
      return "failed to create socket";
    }
    case Error::kSocketOptFailed: {
      return "`getsockopt`/`setsockopt` failed";
    }
    case Error::kSocketInvalidAiFamily: {
      return "invalid socket AI family";
    }
    case Error::kConnectionRefused: {
      return "connection refused";
    }
    case Error::kNetworkUnreachable: {
      return "network unreachable";
    }
    case Error::kSocketPollFailed: {
      return "socket poll failed";
    }
    case Error::kInvalidCertificate: {
      return "invalid certificate";
    }
    case Error::kUnsupportedCertificate: {
      return "unsupported certificate";
    }
    case Error::kInvalidPrivateKey: {
      return "invalid private key";
    }
    case Error::kUnsupportedPrivateKey: {
      return "unsupported private key";
    }
    case Error::kUnsupportedProtocolVersion: {
      return "unsupported protocol version";
    }
    default: {
      return "unknown error code";
    }
  }
}

auto GetStringError(const enum tunnel::RecordError err) -> std::string_view {
  switch (err) {
    case tunnel::RecordError::kOk: {
      return "no error";
    }
    case tunnel::RecordError::kWantRead: {
      return "wants to read data, but the underlying I/O interface is "
             "non-blocking";
    }
    case tunnel::RecordError::kWantWrite: {
      return "wants to write data, but the underlying I/O interface is "
             "non-blocking";
    }
    case tunnel::RecordError::kBeingShutdown: {
      return "tunnel is being close";
    }
    case tunnel::RecordError::kClosed: {
      return "tunnel is closed";
    }
    case tunnel::RecordError::kUnknown: {
      return "unknown error";
    }
    default: {
      return "unknown record plane error code";
    }
  }
}

auto GetStringError(const enum io::IOError err) -> std::string_view {
  switch (err) {
    case io::IOError::kOk: {
      return "no error";
    }
    case io::IOError::kInProgress: {
      return "connection in progress";
    }
    case io::IOError::kWouldBlock: {
      return "the i/o operation would block";
    }
    case io::IOError::kRefused: {
      return "the I/O interface has been refused connection";
    }
    case io::IOError::kClosed: {
      return "the I/O interface is closed";
    }
    case io::IOError::kInvalid: {
      return "the I/O interface isn't valid";
    }
    case io::IOError::kUnknown: {
      return "the I/O interface raised an unknown error";
    }
    default: {
      return "unknown IO error code";
    }
  }
}

auto GetStringError(const enum tunnel::State err) -> std::string_view {
  switch (err) {
    case tunnel::State::kNotConnected: {
      return "not connected";
    }
    case tunnel::State::kConnectionInProgress: {
      return "connection in progress";
    }
    case tunnel::State::kHandshakeInProgress: {
      return "handshake in progress";
    }
    case tunnel::State::kHandshakeDone: {
      return "handshake done";
    }
    case tunnel::State::kBeingShutdown: {
      return "being shutdown";
    }
    case tunnel::State::kDisconnected: {
      return "disconnected";
    }
    case tunnel::State::kError: {
      return "error";
    }
    default: {
      return "unknown tunnel state code";
    }
  }
}

auto GetStringError(const enum tunnel::HandshakeState err) -> std::string_view {
  switch (err) {
    case tunnel::HandshakeState::kInProgress: {
      return "in progress";
    }
    case tunnel::HandshakeState::kDone: {
      return "done";
    }
    case tunnel::HandshakeState::kWantRead: {
      return "the implementation wants to read from the wire, but the "
             "underlying I/O is non-blocking";
    }
    case tunnel::HandshakeState::kWantWrite: {
      return "the implementation wants to write to the wire, but the "
             "underlying I/O is non-blocking";
    }
    case tunnel::HandshakeState::kError: {
      return "a critical error occurred";
    }
    default: {
      return "unknown handshake state code";
    }
  }
}

} // end namespace saq::sandwich
