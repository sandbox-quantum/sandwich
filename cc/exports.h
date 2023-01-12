#pragma once

#if defined _WIN32 || defined __CYGWIN__
#ifdef sandwich_CC_EXPORTS
#ifdef __GNUC__
#define SANDWICH_CC_API __attribute__((dllexport))
#else
#define SANDWICH_CC_API __declspec(dllexport)
#endif
#else
#ifdef __GNUC__
#define SANDWICH_CC_API __attribute__((dllimport))
#else
#define SANDWICH_CC_API __declspec(dllimport)
#endif
#endif
#define DLL_LOCAL
#else
#if __GNUC__ >= 4
#define SANDWICH_CC_API __attribute__((visibility("default")))
#else
#define SANDWICH_CC_API
#endif
#endif
