// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Error tests for the C API interface.
///         Based off tunnels_test.cc
///
/// \author isaleh-sb

#include <array>
#include <thread>

#include "proto/api/v1/configuration.pb.h"
#include "proto/sandwich.pb.h"

#include "tools/cpp/runfiles/runfiles.h"

extern "C" {

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "sandwich_c/sandwich.h"

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#endif

#ifndef __FILE_NAME__
#define __FILE_NAME__ __FILE__
#endif
/** \brief Prints sandwich error and abort on condition.
 *
 * \param e The condition. */
#define sandwich_assert(e)                                                     \
  ((void)((e) ? ((void)0)                                                      \
              : ((void)fprintf(stderr, "%s:%d: failed assertion '%s'\n",       \
                               __FILE_NAME__, __LINE__, #e),                   \
                 abort())))
/** \brief Compare two C strings, prints sandwich error and abort on failure.
 *
 * \param  The condition. */
#define sandwich_str_assert(a, b)                                              \
  ((void)((strcmp(a, b) == 0)                                                  \
              ? ((void)0)                                                      \
              : ((void)fprintf(stderr, "%s:%d: failed assertion '%s'!='%s'\n", \
                               __FILE_NAME__, __LINE__, a, b),                 \
                 abort())))
} // end extern "C"

using bazel::tools::cpp::runfiles::Runfiles;

namespace {
/// \brief Simple message buffer.
using MsgBuffer = std::array<std::byte, 4>;

/// \brief Create a configuration.
///
/// \param mode Mode.
/// \param impl Implementation.
///
/// \return The configuration.
auto NewTLSConfiguration(
    const saq::sandwich::proto::Mode mode,
    const saq::sandwich::proto::api::v1::Implementation impl)
    -> saq::sandwich::proto::api::v1::Configuration {
  saq::sandwich::proto::api::v1::Configuration config{};

  config.set_impl(impl);

  if (mode == saq::sandwich::proto::Mode::MODE_CLIENT) {
    config.mutable_client()->mutable_tls()->mutable_common_options();
  } else if (mode == saq::sandwich::proto::Mode::MODE_SERVER) {
    config.mutable_server()->mutable_tls()->mutable_common_options();
  }

  return config;
}

/// Remove Newline function.
auto chomp(const char *in) {
  std::string s = in;
  for (int p = s.find("\n"); p != (int)std::string::npos; p = s.find("\n"))
    s.erase(p, 1);
  return s;
}

/// \brief Deleter for SandwichContext.
using SandwichContextDeleter = std::function<void(struct ::SandwichContext *)>;

/// \brief Deleter for SandwichTunnelContext
using SandwichTunnelContextDeleter =
    std::function<void(struct ::SandwichTunnelContext *)>;

/// \brief Create an Invalid Sandwich context for the server and test Error
/// Message Expects.
///
/// \param runfiles Bazel runfiles context.
///
/// \return A Sandwich context for the server.
auto TestInvalidServerContextCreation(std::unique_ptr<Runfiles> &runfiles)
    -> std::unique_ptr<struct ::SandwichTunnelContext,
                       SandwichTunnelContextDeleter> {
  auto config{NewTLSConfiguration(saq::sandwich::proto::Mode::MODE_SERVER,
                                  saq::sandwich::proto::api::v1::
                                      Implementation::IMPL_OPENSSL1_1_1_OQS)};

  config.mutable_server()->mutable_tls()->mutable_common_options()->add_kem(
      "kyber1024");
  config.mutable_server()
      ->mutable_tls()
      ->mutable_common_options()
      ->mutable_empty_verifier();

  auto *cert = config.mutable_server()
                   ->mutable_tls()
                   ->mutable_common_options()
                   ->mutable_identity()
                   ->mutable_certificate()
                   ->mutable_static_();
  cert->mutable_data()->set_filename(runfiles->Rlocation(
      "sandwich/testdata/falcon1024.cert.pem"));
  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_PEM);

  auto *key = config.mutable_server()
                  ->mutable_tls()
                  ->mutable_common_options()
                  ->mutable_identity()
                  ->mutable_private_key()
                  ->mutable_static_();
  key->mutable_data()->set_filename(runfiles->Rlocation(
      "sandwich/testdata/falcon1024.key.pem"));
  key->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                      ENCODING_FORMAT_PEM);

  std::string encoded_configuration{};
  sandwich_assert(config.SerializeToString(&encoded_configuration) == true);

  struct ::SandwichTunnelContext *ctx = nullptr;
  SandwichTunnelContextConfigurationSerialized serialized = {
      .src = encoded_configuration.data(),
      .n = encoded_configuration.size(),
  };

  std::unique_ptr<struct SandwichContext, SandwichContextDeleter> sw(
      ::sandwich_lib_context_new(),
      [](struct SandwichContext *sw) { ::sandwich_lib_context_free(sw); });

  const auto *null_err = ::sandwich_tunnel_context_new(&*sw, serialized, &ctx);
  sandwich_assert(null_err == nullptr);

  const auto *err_stack_str_null = ::sandwich_error_stack_str_new(null_err);
  sandwich_str_assert(chomp(err_stack_str_null).c_str(), "Error Stack:");
  ::sandwich_error_stack_str_free(err_stack_str_null);

  std::string invalid_config = "invalid_config";
  serialized.src = invalid_config.data();
  serialized.n = invalid_config.size();
  const auto *err_invalid_config =
      ::sandwich_tunnel_context_new(&*sw, serialized, &ctx);

  const char *expected_err =
      "Error Stack:err:[API errors. The following errors can occur during a "
      "call to the Context API.: Configuration "
      "error.],code:[0,0],msg:[]]err:[Errors regarding protobuf.: Failed to "
      "parse the protobuf message.],code:[6,2],msg:[]]";
  sandwich_assert(err_invalid_config != nullptr);
  const auto *err_stack_str_invalid_config =
      ::sandwich_error_stack_str_new(err_invalid_config);
  sandwich_str_assert(chomp(err_stack_str_invalid_config).c_str(),
                      expected_err);
  ::sandwich_error_stack_str_free(err_stack_str_invalid_config);

  return {ctx, [](struct ::SandwichTunnelContext *c) {
            ::sandwich_tunnel_context_free(c);
          }};
}

} // end anonymous namespace

int main(int argc, char **argv) {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(
      Runfiles::CreateForTest(BAZEL_CURRENT_REPOSITORY, &error));
  sandwich_assert(runfiles != nullptr);

  auto server = TestInvalidServerContextCreation(runfiles);

  return 0;
}
