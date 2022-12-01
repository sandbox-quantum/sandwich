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
    -> Result<DataSource, Error> {
  if (proto.has_filename()) {
    return {Src{FilePath{proto.filename()}}};
  }

  if (auto *str = proto.release_inline_bytes()) {
    return {Src{RawData{std::move(*str)}}};
  }

  if (auto *str = proto.release_inline_string()) {
    return {Src{RawData{std::move(*str)}}};
  }

  return Error::kInvalidConfiguration;
}

auto DataSource::fromProto(const proto::api::v1::DataSource &proto)
    -> Result<DataSource, Error> {
  if (proto.has_filename()) {
    return {Src{FilePath{proto.filename()}}};
  }

  if (proto.has_inline_bytes()) {
    return {Src{RawData{proto.inline_bytes()}}};
  }

  if (proto.has_inline_string()) {
    return {Src{RawData{proto.inline_string()}}};
  }

  return Error::kInvalidConfiguration;
}

} // namespace saq::sandwich
