// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

#pragma once

#if (defined(__clang__) || (_GNUC__ >= 4))
#define SANDWICH_API __attribute__((visibility("default")))
#else
#define SANDWICH_API
#endif
