///
/// \file
/// \brief I/O layer specification.
///
/// All I/O ops are done by the I/O layer. This brings flexibility
/// to Sandwich.
///
/// \author thb-sb

#pragma once

#include <cstddef>
#include <memory>
#include <span>

#include "cc/io/ioerrors.h"
#include "cc/tunnel_state.h"

namespace saq::sandwich::io {

/// \brief I/O layer.
class IO {
 public:
  /// \brief An alias to the public enum IOError.
  using Error = IOError;

  /// \brief A result of an I/O operation.
  ///
  /// An I/O op is described by two values: an error code, and optionally
  /// a size.
  struct OpResult {
    /// \brief Read or written bytes.
    std::size_t count{0};

    /// \brief The error code. Error::Ok if the I/O operation succeeded.
    Error err{Error::kOk};
  };

  /// \brief Writes to the endpoint.
  ///
  /// \param[in] buffer Buffer to write.
  /// \param state Current state of the tunnel.
  ///
  /// \return A result.
  [[nodiscard]] virtual auto Write(std::span<const std::byte> buffer,
                                   tunnel::State state) -> OpResult = 0;

  /// \brief Read from the endpoint.
  ///
  /// \param[in] buffer Buffer where to store read bytes.
  /// \param state Current state of the tunnel.
  ///
  /// \return A result.
  [[nodiscard]] virtual auto Read(std::span<std::byte> buffer,
                                  tunnel::State state) -> OpResult = 0;

  /// \brief Flush the I/O interface.
  virtual inline void Flush() noexcept {}

  /// \brief Close the I/O interface.
  ///
  /// \return A result.
  virtual void Close() = 0;

  /// \brief Get the last saved error.
  ///
  /// \return The last saved error.
  [[nodiscard]] inline auto GetError() const noexcept -> Error {
    return error_;
  }

  /// \brief Constructor.
  IO() noexcept = default;

  /// \brief Copy constructor, deleted.
  IO(const IO &) noexcept = delete;

  /// \brief Move constructor.
  IO(IO &&) = default;

  /// \brief Copy assignment, deleted.
  auto operator=(const IO &) noexcept -> IO & = delete;

  /// \brief Move assignment.
  auto operator=(IO &&) noexcept -> IO & = default;

  /// \brief Destructor.
  virtual ~IO();

 protected:
  /// \brief Save the last error.
  ///
  /// \param err Error to save.
  ///
  /// \return The error saved.
  inline auto SetError(Error err) noexcept { return (error_ = err); }

 private:
  /// \brief Last saved error.
  Error error_ = Error::kOk;
};

} // end namespace saq::sandwich::io
