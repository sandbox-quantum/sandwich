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
/// \brief Structured error API implementation.
///
/// \author thb-sb

#include "cc/error.h"

#include <algorithm>
#include <cassert>

namespace saq::sandwich::error {

[[nodiscard]] auto ErrorCode::operator==(const ErrorCode &ec) const noexcept
    -> bool {
  return (kind == ec.kind) && (code == ec.code);
}

[[nodiscard]] auto ErrorCode::operator==(const ErrorCode *ec) const noexcept
    -> bool {
  return (ec != nullptr) && operator==(*ec);
}

void FreeChain(ErrorCode *chain) noexcept {
  while (chain != nullptr) {
    auto *tmp = chain->details;
    chain->details = nullptr;
    delete chain;
    chain = tmp;
  }
}

Error::Error(ErrorCode *ec) noexcept : err_{ec} {}

Error::Error(Error &&err) noexcept {
  std::swap(err_, err.err_);
  assert(err.err_ == nullptr);
}

auto Error::operator=(Error &&err) noexcept -> Error & {
  if (err_ != nullptr) {
    FreeChain();
  }
  std::swap(err_, err.err_);
  assert(err.err_ == nullptr);
  return *this;
}

Error::~Error() noexcept {
  FreeChain();
}

auto Error::operator>>(Error &&parent_error) noexcept -> Error {
  parent_error.err_->details = Release();
  return parent_error;
}

auto Error::operator>>(ErrorCode *parent_error) noexcept -> Error {
  return this->operator>>(Error{parent_error});
}

auto Error::operator==(const Error &b) const noexcept -> bool {
  if (err_ == b.err_) {
    return true;
  }
  if (!(*this && b)) {
    return false;
  }
  if (err_->kind != b.err_->kind) {
    return false;
  }
  if (err_->code != b.err_->code) {
    return false;
  }
  return true;
}

auto Error::Release() noexcept -> ErrorCode * {
  ErrorCode *tmp{nullptr};
  std::swap(tmp, err_);
  return tmp;
}

void Error::FreeChain() noexcept {
  error::FreeChain(err_);
  err_ = nullptr;
}

Error::Iterator::Iterator(const ErrorCode *ec) noexcept : cur_{ec} {}

auto Error::Iterator::operator*() const noexcept -> const value_type & {
  return *cur_;
}

auto Error::Iterator::operator++() noexcept -> Iterator & {
  cur_ = cur_->details;
  return *this;
}

auto Error::Iterator::operator++(int) noexcept -> Iterator & {
  auto &tmp = *this;
  ++(*this);
  return tmp;
}

auto Error::Iterator::operator==(const Iterator &b) const noexcept -> bool {
  return cur_ == b.cur_;
}

auto Error::Iterator::operator!=(const Iterator &b) const noexcept -> bool {
  return cur_ != b.cur_;
}

auto Error::begin() const noexcept -> Iterator {
  return Iterator{err_};
}

} // end namespace saq::sandwich::error
