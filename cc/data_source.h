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
/// \brief Sandwich context specification.
///
/// \author ag-sb

#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>

#include "cc/errors.h"
#include "cc/result.h"
#include "proto/api/v1/data_source.pb.h"

namespace saq::sandwich {

class DataSource {
 public:
  // \brief Create a DataSource object from a protobuf definition.
  static auto fromProto(const proto::api::v1::DataSource &proto)
      -> Result<DataSource, Error>;

  // \brief Create a DataSource object from a protobuf definition.
  //
  // It will release data away from `proto' (and prevents copying the
  // underlying data if they exist).
  static auto fromProto(proto::api::v1::DataSource &&proto)
      -> Result<DataSource, Error>;

  DataSource(const DataSource &) = default;
  DataSource(DataSource &&) = default;
  DataSource &operator=(DataSource &&) = default;
  DataSource &operator=(const DataSource &) = default;

  std::optional<std::string_view> path() const;
  std::optional<std::span<const std::byte>> rawData() const;

 private:
  struct FilePath {
    std::string path;
  };
  struct RawData {
    // AG: std::vector<std::byte> would have been cleaner, but protobuf
    // generates std::string objects...
    std::string data;
  };
  using Src = std::variant<FilePath, RawData>;
  Src src_;

  DataSource(Src &&src);
};

} // namespace saq::sandwich
