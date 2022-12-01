/**
 * \file
 * \brief Enum RecordError in namespace SandwichTunnel.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Enum RecordError. */
enum SandwichTunnelRecordError { 
  SANDWICH_TUNNEL_RECORDERROR_OK = 0,
  SANDWICH_TUNNEL_RECORDERROR_WANT_READ = 1,
  SANDWICH_TUNNEL_RECORDERROR_WANT_WRITE = 2,
  SANDWICH_TUNNEL_RECORDERROR_BEING_SHUTDOWN = 3,
  SANDWICH_TUNNEL_RECORDERROR_CLOSED = 4,
  SANDWICH_TUNNEL_RECORDERROR_UNKNOWN = 5,
};
typedef enum SandwichTunnelRecordError SandwichTunnelRecordError;

#ifdef __cplusplus
} // end extern "C"
#endif
