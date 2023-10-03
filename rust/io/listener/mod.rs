// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

/// A Listener.
pub trait Listener {
    /// Similar to the linux system call `listen`. Sets up the listener to
    /// accept incoming connections.
    fn listen(&mut self) -> Result<(), std::io::Error>;

    /// Similar to the linux system call `accept`. Accepts incoming
    /// connection requests based on parameters set by `self.listen()`.
    fn accept(&mut self) -> Result<Box<dyn crate::IO>, std::io::Error>;

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
    if let Some(mode) = configuration.mode.as_ref() {
        match mode {
            pb_api::listener_configuration::listener_configuration::Mode::Tcp(m) => {
                let addr = match m.addr.as_ref() {
                    Some(a) => a,
                    None => {
                        return Err(
                            pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER.into()
                        )
                    }
                };
                let is_blocking = if let Ok(blocking_mode) = m.blocking_mode.enum_value() {
                    match blocking_mode {
                        pb_api::listener_configuration::BlockingMode::BLOCKINGMODE_BLOCKING => true,
                        pb_api::listener_configuration::BlockingMode::BLOCKINGMODE_NONBLOCKING => {
                            false
                        }
                        pb_api::listener_configuration::BlockingMode::BLOCKINGMODE_UNSPECIFIED => {
                            return Err(
                                pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER.into(),
                            );
                        }
                    }
                } else {
                    return Err(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER.into());
                };
                if let Ok(io) = crate::io::helpers::tcp::TcpListener::new(
                    addr.hostname.as_str().to_owned() + ":" + &addr.port.to_string(),
                    is_blocking,
                ) {
                    Ok(Box::new(io))
                } else {
                    Err(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER.into())
                }
            }
            _ => Err(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER.into()),
        }
    } else {
        Err(pb::ConfigurationError::CONFIGURATIONERROR_INVALID_LISTENER.into())
    }
}

#[cfg(test)]
pub(crate) mod test {

    #[test]
    fn test_listener_configuration() {
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
