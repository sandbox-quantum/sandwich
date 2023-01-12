/*
 * Copyright 2022 SandboxAQ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

///
/// \file
/// \brief I/O layer implementation using a socket, specification.
///
/// \author thb-sb

#pragma once

#include <cstdint>
#include <forward_list>
#include <iterator>
#include <string>

#include "cc/errors.h"
#include "cc/io/io.h"
#include "cc/result.h"
#include "proto/sandwich.pb.h"

extern "C" {

#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>
}

namespace saq::sandwich::io {

/// \brief Wrapper around a file descriptor.
class FileDescriptor {
 public:
  /// \brief An invalid file descriptor.
  static constexpr int kInvalidFd = -1;

  /// \brief Factory, using an existing file descriptor.
  ///
  /// \param fdesc File descriptor.
  ///
  /// \return A FileDescriptor, or an error.
  [[nodiscard]] static auto New(int fdesc)
      -> Result<FileDescriptor, sandwich::Error>;

  /// \brief Casts to the file descriptor.
  ///
  /// \return The file descriptor.
  [[nodiscard]] inline operator int() const noexcept { return fd_; }

  /// \brief Returns the file descriptor.
  ///
  /// \return The file descriptor.
  [[nodiscard]] inline auto Get() const noexcept -> int { return fd_; }

  /// \brief Release the file descriptor.
  ///
  /// It will not be closed by the destructor.
  ///
  /// \return The file descriptor.
  inline auto Release() noexcept -> int {
    auto tmp = kInvalidFd;
    std::swap(tmp, fd_);
    return tmp;
  }

  /// \brief Copy constructor, deleted.
  FileDescriptor(const FileDescriptor &) noexcept = delete;

  /// \brief Move constructor.
  FileDescriptor(FileDescriptor &&) noexcept;

  /// \brief Copy assignment.
  auto operator=(const FileDescriptor &) noexcept -> FileDescriptor & = delete;

  /// \brief Move assignment.
  auto operator=(FileDescriptor &&) noexcept -> FileDescriptor &;

  /// \brief Destructor
  ~FileDescriptor() noexcept;

 private:
  /// \brief Constructor, from a valid file descriptor.
  explicit FileDescriptor(int fdesc) noexcept;

  /// \brief The file descriptor.
  int fd_ = kInvalidFd;
};

/// \brief A network address.
struct NetworkAddress {
  union {
    /// \brief IPv4 address.
    ::sockaddr_in i4;

    /// \brief IPv6 address.
    ::sockaddr_in6 i6;
  } addr;

  /// \brief Len
  ::socklen_t len = 0;

  /// \brief Family
  int ai_family = 0;
};

/// \brief A I/O layer, using a socket.
class Socket : public IO {
 public:
  /// \brief Create a socket from a file descriptor.
  ///
  /// \param fdesc File descriptor.
  ///
  /// \return A socket, or an error.
  [[nodiscard]] static auto FromFd(int fdesc)
      -> Result<std::unique_ptr<IO>, sandwich::Error>;

  /// \brief Create a socket from a file descriptor wrapper.
  ///
  /// \param fdesc File descriptor.
  ///
  /// \return A socket, or an error.
  [[nodiscard]] static auto FromFd(FileDescriptor fdesc)
      -> Result<std::unique_ptr<IO>, sandwich::Error>;

  /// \brief Copy constructor.
  Socket(const Socket &) noexcept = delete;

  /// \brief Move constructor.
  Socket(Socket &&) noexcept;

  /// \brief Copy assignment.
  auto operator=(const Socket &) noexcept -> Socket & = delete;

  /// \brief Move assignment.
  auto operator=(Socket &&) noexcept -> Socket &;

  /// \brief Destructor.
  ~Socket() override;

  [[nodiscard]] auto Write(std::span<const std::byte> buffer,
                           tunnel::State state) -> OpResult override;
  [[nodiscard]] auto Read(std::span<std::byte> buffer, tunnel::State state)
      -> OpResult override;
  void Close() override;

  /// \brief Poll events.
  enum class PollEvent : int {
    /// \brief There is data to read.
    kRead = POLLIN,
    /// \brief Data can be written.
    kWrite = POLLOUT,
    /// \brief An error occured.
    kError = POLLERR,
    /// \brief Hang up.
    kHangUp = POLLHUP,
  };

  /// \brief Poll the socket,
  ///
  /// \param events OR-bitwise events to watch for,
  /// \param timeout Timeout in milliseconds.
  ///
  /// If no timeout is specified, `poll` will wait indefinitely.
  ///
  /// \return OR-bitwise event, or an error code.
  auto Poll(int events, std::optional<int> timeout) -> Result<int, Error>;

 protected:
  /// \brief Returns the underlying socket.
  ///
  /// \return The underlying socket.
  [[nodiscard]] inline auto GetFd() noexcept -> FileDescriptor & { return fd_; }

  /// \brief Returns the underlying socket.
  ///
  /// \return The underlying socket.
  [[nodiscard]] inline auto GetFd() const noexcept -> const FileDescriptor & {
    return fd_;
  }

 private:
  /// \brief Constructor, using an open socket.
  ///
  /// \param sock The socket.
  /// \param netaddr The network address.
  explicit Socket(FileDescriptor sock, const NetworkAddress &netaddr) noexcept;

  /// \brief Returns the socket error, using `getsockopt`.
  ///
  /// \return The socket error.
  [[nodiscard]] auto GetSocketError() const noexcept
      -> Result<int, sandwich::Error>;

  /// \brief The underlying socket.
  FileDescriptor fd_;

  /// \brief The network address.
  const NetworkAddress addr_;
};

} // end namespace saq::sandwich::io
