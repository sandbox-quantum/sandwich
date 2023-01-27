/*
 * Copyright 2023 SandboxAQ
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

/// \file
/// \brief Structured error API.
///
/// \author thb-sb

#pragma once

#include <iterator>
#include <type_traits>

#include "cc/error_codes.h"

namespace saq::sandwich::error {

/// \brief Concept of an error code.
///
/// This concept defines a type as a valid Sandwich error code.
///
/// \param T type to check.
template <typename T>
concept ErrorCodeEnum =
    std::is_same_v<T, APIError> || std::is_same_v<T, ConfigurationError> ||
    std::is_same_v<T, OpenSSLConfigurationError> ||
    std::is_same_v<T, OpenSSLClientConfigurationError> ||
    std::is_same_v<T, CertificateError> || std::is_same_v<T, SystemError> ||
    std::is_same_v<T, SocketError> || std::is_same_v<T, ProtobufError> ||
    std::is_same_v<T, OpenSSLServerConfigurationError> ||
    std::is_same_v<T, PrivateKeyError> || std::is_same_v<T, ASN1Error> ||
    std::is_same_v<T, DataSourceError> || std::is_same_v<T, KEMError>;

/// \brief Get the ErrorKind from an enum type.
///
/// \tparam Enum Enum type.
///
/// \return The associated ErrorKind.
template <ErrorCodeEnum Enum>
[[nodiscard]] constexpr auto ToErrorKind() noexcept -> ErrorKind {
  if constexpr (std::is_same_v<Enum, APIError>) {
    return ErrorKind::kApi;
  } else if constexpr (std::is_same_v<Enum, ConfigurationError>) {
    return ErrorKind::kConfiguration;
  } else if constexpr (std::is_same_v<Enum, OpenSSLConfigurationError>) {
    return ErrorKind::kOpensslConfiguration;
  } else if constexpr (std::is_same_v<Enum, OpenSSLClientConfigurationError>) {
    return ErrorKind::kOpensslClientConfiguration;
  } else if constexpr (std::is_same_v<Enum, CertificateError>) {
    return ErrorKind::kCertificate;
  } else if constexpr (std::is_same_v<Enum, SystemError>) {
    return ErrorKind::kSystem;
  } else if constexpr (std::is_same_v<Enum, SocketError>) {
    return ErrorKind::kSocket;
  } else if constexpr (std::is_same_v<Enum, ProtobufError>) {
    return ErrorKind::kProtobuf;
  } else if constexpr (std::is_same_v<Enum, OpenSSLServerConfigurationError>) {
    return ErrorKind::kOpensslServerConfiguration;
  } else if constexpr (std::is_same_v<Enum, PrivateKeyError>) {
    return ErrorKind::kPrivateKey;
  } else if constexpr (std::is_same_v<Enum, ASN1Error>) {
    return ErrorKind::kAsn1;
  } else if constexpr (std::is_same_v<Enum, DataSourceError>) {
    return ErrorKind::kDataSource;
  } else if constexpr (std::is_same_v<Enum, KEMError>) {
    return ErrorKind::kKem;
  }

  else {
    []<bool flag = false> {
      static_assert(flag, "Invalid Enum type");
    }
    ();
  }
};

/// \brief An error code.
///
/// An error code describes an error along with its kind.
/// The kind of error it basically the enum to which the error code belongs.
/// The error code actually describe the error.
///
/// An error code can also encapsulates another error. The encapsulated error
/// is meant to be more precise about the error. For instance,
/// CertificateError::kMalformed can encapsulate ASN1Error::kInvalidFormat.
/// The latter gives more information about the former.
/// This is built using a linked list, where the `details` points to the
/// encapsulated error.
struct ErrorCode {
  /// \brief The encapsulated error.
  ErrorCode *details{nullptr};

  /// \brief The error kind. See error::ErrorKind enum.
  ErrorKind kind;

  /// \brief The actual error code.
  int code;

  /// \brief Compare the error code with an enum code.
  ///
  /// \tparam Enum Enum type.
  ///
  /// \param code Code.
  ///
  /// \return true if same, else false.
  template <ErrorCodeEnum Enum>
  [[nodiscard]] auto operator==(const Enum code) const noexcept -> bool {
    return kind == ToErrorKind<Enum>() && this->code == static_cast<int>(code);
  }

  /// \brief Compare the error code with another error code.
  ///
  /// \param ec The other error code.
  ///
  /// \return true if same, else false.
  [[nodiscard]] auto operator==(const ErrorCode &ec) const noexcept -> bool;
  [[nodiscard]] auto operator==(const ErrorCode *ec) const noexcept -> bool;
};

/// \brief Create a new ErrorCode from an enum value.
///
/// The kind of error is resolved using ToErrorKind.
///
/// \tparam Enum Enum type.
///
/// \param code Error code.
///
/// \return A new ErrorCode.
template <ErrorCodeEnum Enum>
[[nodiscard]] constexpr auto New(const Enum code) -> ErrorCode * {
  return new ErrorCode{
      .kind = ToErrorKind<Enum>(),
      .code = static_cast<int>(code),
  };
}

/// \brief Create an error code from two enum values.
///
/// \param cause The cause of `error`.
/// \param error The error to create.
///
/// Using the operator, the `cause` error will be wrapped into `error`.
///
/// \return An error code.
template <ErrorCodeEnum C, ErrorCodeEnum E>
[[nodiscard]] auto operator>>(const C cause, const E error) -> ErrorCode * {
  if (auto *e = New(error); e != nullptr) {
    if (e->details = New(cause); e->details == nullptr) {
      delete e;
      e = nullptr;
    }
    return e;
  }
  return nullptr;
}

/// \brief Encapsulate an error code into another, using an enum value.
///
/// \tparam Enum Enum type.
///
/// \param ec_cause Error code.
/// \param code_error Enum value.
///
/// `value` will wrap `ec`.
///
/// \return The new error code.
template <ErrorCodeEnum Enum>
[[nodiscard]] auto operator>>(ErrorCode *ec_cause, const Enum code_error)
    -> ErrorCode * {
  auto *e = New(code_error);
  if (e != nullptr) {
    e->details = ec_cause;
  }
  return e;
}

/// \brief Free an error code chain.
///
/// \param chain Error code chain.
void FreeChain(ErrorCode *chain) noexcept;

/// \brief Empty type, matching an empty error (case 'ok').
///
/// This empty type is used to construct an empty error using
/// `return error::Ok` instead of `return {}`.
struct Ok_t {
  inline explicit constexpr Ok_t([[maybe_unused]] const int o) noexcept {}
};

/// \brief Constant of type Ok_t that is used to indicate a no-error case.
static constexpr Ok_t Ok{0};

/// \brief A convenient wrapper around ErrorCode.
///
/// This structure wraps an ErrorCode and exposes convenient methods
/// such as operator>>(ParentError) to build the chain of error.
class Error {
 public:
  /// \brief Iterator over ErrorCode.
  class Iterator {
    using iterator_category = std::input_iterator_tag;
    using value_type = ErrorCode;

   public:
    /// \brief Construct an invalid iterator.
    constexpr Iterator() noexcept = default;

    /// \brief Construct an iterator from an ErrorCode pointer.
    ///
    /// \param ec ErrorCode pointer.
    Iterator(const ErrorCode *ec) noexcept;

    /// \brief Implement operator*.
    ///
    /// \return The const reference.
    auto operator*() const noexcept -> const value_type &;

    /// \brief Implement operator++.
    ///
    /// \return The new iterator.
    auto operator++() noexcept -> Iterator &;

    /// \brief Postfix increment.
    ///
    /// \return The new iterator.
    auto operator++(int) noexcept -> Iterator &;

    /// \brief Implement comparison.
    auto operator==(const Iterator &b) const noexcept -> bool;
    /// \brief Implement comparison.
    auto operator!=(const Iterator &b) const noexcept -> bool;

   private:
    const ErrorCode *cur_{nullptr};
  };

  /// \brief Construct an empty Error (no error).
  inline constexpr Error() noexcept = default;

  /// \brief Construct an empty Error using the Ok type.
  inline constexpr Error([[maybe_unused]] const Ok_t &ok) noexcept : Error{} {};

  /// \brief Construct an error from an enum value.
  ///
  /// \tparam Enum Enum type.
  ///
  /// \param code Error code.
  template <ErrorCodeEnum Enum>
  constexpr Error(const Enum code) : err_{New(code)} {}

  /// \brief Construct an error from an ErrorCode.
  ///
  /// \param ec Error code.
  Error(ErrorCode *ec) noexcept;

  /// \brief Copy constructor.
  Error(const Error &) noexcept = delete;

  /// \brief Move constructor.
  Error(Error &&err) noexcept;

  /// \brief Copy assignment.
  auto operator=(const Error &) noexcept -> Error & = delete;

  /// \brief Move assignment.
  auto operator=(Error &&) noexcept -> Error &;

  /// \brief Destructor.
  ~Error() noexcept;

  /// \brief Cast to ErrorCode.
  [[nodiscard]] inline operator ErrorCode &() noexcept { return *err_; }

  /// \brief Cast to ErrorCode.
  [[nodiscard]] inline operator const ErrorCode &() const noexcept {
    return *err_;
  }

  /// \brief Return true if an error is stored in the Error wrapper.
  ///
  /// \return true if an error is stored, else false.
  [[nodiscard]] inline operator bool() const noexcept {
    return err_ != nullptr;
  }

  /// \brief Get the error code.
  ///
  /// \return The error code.
  [[nodiscard]] inline auto Code() const noexcept -> const ErrorCode & {
    return *err_;
  }

  /// \brief Encapsulate the current error into a new error.
  ///
  /// \param parent_error The parent error.
  ///
  /// \return The new error chain.
  [[nodiscard]] auto operator>>(Error &&parent_error) noexcept -> Error;

  /// \brief Encapsulate the current error into a new error from an Error Code.
  ///
  /// \param parent_error The parent error.
  ///
  /// \return The new error chain.
  [[nodiscard]] auto operator>>(ErrorCode *parent_error) noexcept -> Error;

  /// \brief Compare the error with the Ok case.
  ///
  /// \return True if same as Ok, else false.
  [[nodiscard]] auto operator==(const Ok_t &o) noexcept -> bool {
    return !*this;
  }

  /// \brief Compare an error with another.
  ///
  /// \param b The other error.
  ///
  /// \return true if same, else false.
  [[nodiscard]] auto operator==(const Error &b) const noexcept -> bool;

  /// \brief Compare an error with an enum code.
  ///
  /// \tparam Enum Enum type.
  ///
  /// \param code Enum code.
  ///
  /// \return true if same, else false.
  template <ErrorCodeEnum Enum>
  [[nodiscard]] auto operator==(Enum code) const noexcept -> bool {
    if (err_ == nullptr) {
      return false;
    }
    return *err_ == code;
  }

  /// \brief Release the pointer to the error chain.
  ///
  /// When released, the ownership is transferred to the caller.
  ///
  /// \return Pointer to the error code.
  [[nodiscard]] auto Release() noexcept -> ErrorCode *;

  /// \brief Create a new iterator from the beginning of the error chain.
  ///
  /// \return New iterator from the beginning of the error chain.
  [[nodiscard]] auto begin() const noexcept -> Iterator;

  /// \brief Create a new iterator from the end of the error chain.
  ///
  /// \return New iterator from the end of the error chain.
  [[nodiscard]] static constexpr auto end() noexcept -> Iterator {
    return Iterator{};
  }

 private:
  /// \brief Free the error chain.
  void FreeChain() noexcept;

  /// \brief Pointer to the encapsulated error.
  ErrorCode *err_{nullptr};
};

} // end namespace saq::sandwich::error
