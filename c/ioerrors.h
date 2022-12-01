/**
 * \file
 * \brief Enum IOError in namespace Sandwich.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Enum IOError. */
enum SandwichIOError { 
  SANDWICH_IOERROR_OK = 0,
  SANDWICH_IOERROR_IN_PROGRESS = 1,
  SANDWICH_IOERROR_WOULD_BLOCK = 2,
  SANDWICH_IOERROR_REFUSED = 3,
  SANDWICH_IOERROR_CLOSED = 4,
  SANDWICH_IOERROR_INVALID = 5,
  SANDWICH_IOERROR_UNKNOWN = 6,
};
typedef enum SandwichIOError SandwichIOError;

#ifdef __cplusplus
} // end extern "C"
#endif
