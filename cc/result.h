///
/// \file
/// \brief Error handling using a Result container, storing either an error
///        or a value.
///
/// \author thb-sb

#pragma once

#include <variant>

namespace saq::sandwich {

/// \brief A container which stores either an object, or an error.
///
/// This container is a copy of the `Result` container in Rust.
///
/// \tparam T Type of the result.
/// \tparam E Type of the error.
template <typename T, typename E>
class Result {
 public:
  /// \brief Index for the undefined type.
  static constexpr std::size_t kUndefinedIndex = 0;

  /// \brief Index for the Result type.
  static constexpr std::size_t kResultIndex = 1;

  /// \brief Index for the Error type.
  static constexpr std::size_t kErrorIndex = 2;

  /// \brief Create a Ok Result.
  ///
  /// \param value Value.
  ///
  /// \return A success result.
  static auto Ok(const T &value) -> Result { return {value, kResultIndex}; }
  static auto Ok(T &&value) -> Result {
    return {std::move(value), kResultIndex};
  }

  /// \brief Create an Error Result.
  ///
  /// \param value Value.
  ///
  /// \return An error result.
  static auto Err(const E &value) -> Result { return {value, kErrorIndex}; }
  static auto Err(E &&value) -> Result {
    return {std::move(value), kErrorIndex};
  }

  /// \brief Constructs a Result from an Error (error case).
  ///
  /// \param e Error.
  Result(const E &e) : value_{std::in_place_index<kErrorIndex>, std::move(e)} {}

  /// \brief Constructs a Result from an object (success case).
  ///
  /// \param o Object.
  Result(const T &o)
      : value_{std::in_place_index<kResultIndex>, std::move(o)} {}

  /// \brief Construct a Result from an Error, by moving its value (error case).
  ///
  /// \param e Error to move.
  Result(E &&e) : value_{std::in_place_index<kErrorIndex>, std::move(e)} {}

  /// \brief Construct a Result fron an object, by moving its value (success
  /// case).
  ///
  // \param o Object to move.
  Result(T &&o) : value_{std::in_place_index<kResultIndex>, std::move(o)} {}

  /// \brief Copy constructor, default.
  Result(const Result &) = default;

  /// \brief Move constructor, default.
  Result(Result &&) = default;

  /// \brief Copy assignment, default.
  auto operator=(const Result &) -> Result & = default;

  /// \brief Move assignment, default.
  auto operator=(Result &&) -> Result & = default;

  /// \brief Destructor, default.
  ~Result() = default;

  /// \brief Returns false if the stored value is an error.
  ///
  /// \return false if Result stores an error, else true.
  operator bool() const noexcept { return value_.index() == kResultIndex; }

  /// \brief Returns the result variant.
  ///
  /// \throw std::bad_variant_access if the Result stores the error variant.
  ///
  /// \return Reference to the result variant.
  auto Get() -> T & { return std::get<kResultIndex>(value_); }

  /// \brief Returns the result variant.
  ///
  /// \throw std::bad_variant_access if the Result stores the error variant.
  ///
  /// \return Reference to the result variant.
  auto Get() const -> const T & { return std::get<kResultIndex>(value_); }

  /// \brief Returns the error variant.
  ///
  /// \throw std::bad_variant_access if the Result stores the result variant.
  ///
  /// \return Reference to the error variant.
  auto GetError() -> E & { return std::get<kErrorIndex>(value_); }

  /// \brief Returns the error variant.
  ///
  /// \throw std::bad_variant_access if the Result stores the result variant.
  ///
  /// \return Reference to the error variant.
  auto GetError() const -> const E & { return std::get<kErrorIndex>(value_); }

  /// \brief Returns pointer to the result variant.
  ///
  /// \throw std::bad_variant_access if the Result stores the error variant.
  ///
  /// \return Pointer to the result variant.
  auto operator->() -> T * { return &this->Get(); }

  /// \brief Returns pointer to the result variant.
  ///
  /// \throw std::bad_variant_access if the Result stores the error variant.
  ///
  /// \return Pointer to the result variant.
  auto operator->() const -> const T * { return &this->Get(); }

 private:
  /// \brief Constructor with explicit index.
  ///
  /// \param value Value.
  /// \param index Index.
  Result(const T &value, std::size_t index) {
    if (index == kResultIndex) {
      value_.emplace<kResultIndex>(value);
    }
  }
  Result(T &&value, std::size_t index) {
    if (index == kResultIndex) {
      value_.emplace<kResultIndex>(std::move(value));
    }
  }

  Result(const E &value, std::size_t index) {
    if (index == kErrorIndex) {
      value_.emplace<kErrorIndex>(value);
    }
  }
  Result(E &&value, std::size_t index) {
    if (index == kErrorIndex) {
      value_.emplace<kErrorIndex>(std::move(value));
    }
  }

  /// \brief Variant type, handling either T or E.
  using VariantT = std::variant<std::monostate, T, E>;

  /// \brief Variant, storing the Result value or the error.
  VariantT value_;
};

} // end namespace saq::sandwich
