// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "ffi")]
use crate::ffi::io::OwnedIo;

/// A listener for connections.
pub trait Listener: Send {
    /// Similar to the linux system call `listen`. Sets up the listener to
    /// accept incoming connections.
    fn listen(&mut self) -> Result<(), std::io::Error>;

    /// Similar to the linux system call `accept`. Accepts incoming
    /// connection requests based on parameters set by `self.listen()`.
    fn accept(&mut self) -> Result<Box<dyn crate::IO>, std::io::Error>;

    /// Similar to [`accept`]. Returns an Owned IO.
    #[cfg(feature = "ffi")]
    fn ffi_accept_owned(&mut self) -> Result<Box<OwnedIo>, std::io::Error> {
        self.accept().map(Box::<OwnedIo>::from)
    }

    /// Closes the listener and rejects all future connection requests.
    fn close(&mut self) -> Result<(), std::io::Error>;

    /// A custom destructor to be called when memory is freed.
    fn destructor(&mut self) -> Result<(), std::io::Error> {
        // This function/field is primarily used for ffi as
        // rust will manage the memory for us. So by default
        // this is a no-op.
        Ok(())
    }
}

/// Instantiates a [`Listener`] from a protobuf configuration message.
#[allow(dead_code)]
pub fn try_from(configuration: &pb_api::ListenerConfiguration) -> crate::Result<Box<dyn Listener>> {
    match configuration
        .mode
        .as_ref()
        .ok_or(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER)?
    {
        pb_api::listener_configuration::listener_configuration::Mode::Tcp(m) => {
            let addr = m
                .addr
                .as_ref()
                .ok_or(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER)?;

            let is_blocking = match m.blocking_mode.enum_value() {
                Ok(pb_api::listener_configuration::BlockingMode::BLOCKINGMODE_BLOCKING) => true,
                Ok(pb_api::listener_configuration::BlockingMode::BLOCKINGMODE_NONBLOCKING) => false,
                _ => return Err(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER.into()),
            };

            let host = addr.hostname.as_str();
            let port = u16::try_from(addr.port)
                .map_err(|_| pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)?;
            let tcp = crate::io::helpers::tcp::TcpListener::new((host, port), is_blocking)
                .map_err(|_| pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER)?;

            Ok(Box::new(tcp))
        }
        #[cfg(feature = "turbo")]
        pb_api::listener_configuration::listener_configuration::Mode::Turbo(m) => {
            let udp_addr = m
                .udp
                .as_ref()
                .ok_or(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER)?;
            let tcp_addr = m
                .tcp
                .as_ref()
                .ok_or(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER)?;

            let is_blocking = match m.blocking_mode.enum_value() {
                Ok(pb_api::listener_configuration::BlockingMode::BLOCKINGMODE_NONBLOCKING) => false,
                _ => {
                    return Err((
                        pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER,
                        "unsupported blocking mode for turbo",
                    )
                        .into())
                }
            };

            let udp_host = udp_addr.hostname.as_str();
            let udp_port = u16::try_from(udp_addr.port)
                .map_err(|_| pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)?;
            let tcp_host = tcp_addr.hostname.as_str();
            let tcp_port = u16::try_from(tcp_addr.port)
                .map_err(|_| pb::SystemError::SYSTEMERROR_INTEGER_OVERFLOW)?;
            let turbo = crate::experimental::turbo::TurboListener::new(
                (udp_host, udp_port),
                (tcp_host, tcp_port),
                is_blocking,
            )
            .map_err(|_| pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER)?;

            Ok(Box::new(turbo))
        }
        #[cfg(not(feature = "turbo"))]
        pb_api::listener_configuration::listener_configuration::Mode::Turbo(_) => Err((
            pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER,
            "this build does not include the turbo feature",
        )
            .into()),
        _ => Err(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER.into()),
    }
}

#[cfg(test)]
pub(crate) mod test {

    #[test]
    fn test_tcp_listener_configuration() {
        let listener_config =
            protobuf::text_format::parse_from_str::<pb_api::ListenerConfiguration>(
                r#"
            tcp <
              addr <
                hostname: "127.0.0.1"
                port: 1337
              >
              blocking_mode: BLOCKINGMODE_NONBLOCKING
            >
            "#,
            )
            .unwrap();
        let l = super::try_from(&listener_config);
        let mut listener = l.unwrap();
        _ = listener.listen();
    }

    #[cfg(feature = "turbo")]
    #[test]
    fn test_turbo_listener_configuration() {
        let listener_config =
            protobuf::text_format::parse_from_str::<pb_api::ListenerConfiguration>(
                r#"
            turbo <
              udp <
                hostname: "127.0.0.1"
                port: 4242
              >
              tcp <
                hostname: "127.0.0.1"
                port: 4242
              >
              blocking_mode: BLOCKINGMODE_NONBLOCKING
            >
            "#,
            )
            .unwrap();
        let l = super::try_from(&listener_config);
        let mut listener = l.unwrap();
        _ = listener.listen();
    }

    #[cfg(feature = "turbo")]
    #[test]
    fn test_bad_turbo_blocking_listener_configuration() {
        let listener_config =
            protobuf::text_format::parse_from_str::<pb_api::ListenerConfiguration>(
                r#"
            turbo <
              udp <
                hostname: "127.0.0.1"
                port: 2424
              >
              tcp <
                hostname: "127.0.0.1"
                port: 2424
              >
              blocking_mode: BLOCKINGMODE_BLOCKING
            >
            "#,
            )
            .unwrap();
        assert!(super::try_from(&listener_config).is_err());
    }

    #[cfg(not(feature = "turbo"))]
    #[test]
    fn test_no_turbo_listener_configuration() {
        let listener_config =
            protobuf::text_format::parse_from_str::<pb_api::ListenerConfiguration>(
                r#"
            turbo <
              udp <
                hostname: "127.0.0.1"
                port: 1337
              >
              tcp <
                hostname: "127.0.0.1"
                port: 7331
              >
              blocking_mode: BLOCKINGMODE_BLOCKING
            >
            "#,
            )
            .unwrap();
        assert!(super::try_from(&listener_config).is_err());
    }

    #[test]
    fn test_listener_bad_blocking_modeconfiguration() {
        let listener_config =
            protobuf::text_format::parse_from_str::<pb_api::ListenerConfiguration>(
                r#"
            tcp <
              addr <
                hostname: "127.0.0.1"
                port: 1337
              >
              blocking_mode: BLOCKINGMODE_UNSPECIFIED
            >
            "#,
            )
            .unwrap();
        assert!(super::try_from(&listener_config).is_err());
    }

    #[test]
    fn test_listener_bad_ip_configuration() {
        let listener_config =
            protobuf::text_format::parse_from_str::<pb_api::ListenerConfiguration>(
                r#"
            tcp <
              addr <
                hostname: "355.0.0.1"
                port: 1337
              >
              blocking_mode: BLOCKINGMODE_NONBLOCKING
            >
            "#,
            )
            .unwrap();
        assert!(super::try_from(&listener_config).is_err());
    }

    #[test]
    fn test_listener_bad_port_configuration() {
        let listener_config =
            protobuf::text_format::parse_from_str::<pb_api::ListenerConfiguration>(
                r#"
        tcp <
          addr <
            hostname: "127.0.0.1"
            port: 1337420
          >
          blocking_mode: BLOCKINGMODE_NONBLOCKING
        >
            "#,
            )
            .unwrap();
        assert!(super::try_from(&listener_config).is_err());
    }
}
