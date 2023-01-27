// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cassert>

#include "cc/data_source.h"

namespace saq::sandwich {

DataSource::DataSource(Src &&src) : src_(std::move(src)) {}

auto DataSource::path() const -> std::optional<std::string_view> {
  const auto *ret = std::get_if<FilePath>(&src_);
  if (ret == nullptr) {
    return {};
  }
  return {ret->path};
}

auto DataSource::rawData() const -> std::optional<std::span<const std::byte>> {
  const auto *ret = std::get_if<RawData>(&src_);
  if (ret == nullptr) {
    return {};
  }
  return {std::span<const std::byte>{
      reinterpret_cast<const std::byte *>(ret->data.data()), ret->data.size()}};
}

auto DataSource::fromProto(proto::api::v1::DataSource &&proto)
    -> Result<DataSource, error::Error> {
  if (proto.has_filename()) {
    return Result<DataSource, error::Error>::Ok(
        Src{FilePath{proto.filename()}});
  }

  if (auto *str = proto.release_inline_bytes()) {
    return Result<DataSource, error::Error>::Ok(
        {Src{RawData{std::move(*str)}}});
  }

  if (auto *str = proto.release_inline_string()) {
    return Result<DataSource, error::Error>::Ok(
        {Src{RawData{std::move(*str)}}});
  }

  return error::DataSourceError::kEmpty;
}

auto DataSource::fromProto(const proto::api::v1::DataSource &proto)
    -> Result<DataSource, error::Error> {
  if (proto.has_filename()) {
    return Result<DataSource, error::Error>::Ok(
        {Src{FilePath{proto.filename()}}});
  }

  if (proto.has_inline_bytes()) {
    return Result<DataSource, error::Error>::Ok(
        {Src{RawData{proto.inline_bytes()}}});
  }

  if (proto.has_inline_string()) {
    return Result<DataSource, error::Error>::Ok(
        {Src{RawData{proto.inline_string()}}});
  }

  return error::DataSourceError::kEmpty;
}

} // namespace saq::sandwich
