///
/// \file
/// \brief Sandwich context implementation.
///
/// \author thb-sb

#include "cc/context.h"

namespace saq::sandwich {

Context::Context(const ProtoConfiguration &config)
    : protocol_{config.protocol()}, implementation_{config.impl()} {}

Context::~Context() = default;

} // end namespace saq::sandwich
