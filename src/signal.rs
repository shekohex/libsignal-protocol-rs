use std::fmt::{self, Display};

use getset::Getters;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Getters)]
pub struct SignalProtocolAddress {
  #[get = "pub"]
  name: String,
  #[get = "pub"]
  device_id: u32,
}

impl SignalProtocolAddress {
  pub fn new(name: String, device_id: u32) -> Self { Self { name, device_id } }
}

impl Display for SignalProtocolAddress {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "{}:{}", self.name, self.device_id)
  }
}

/// `SessionBuilder` is responsible for setting up encrypted sessions.
///
/// Once a session has been established,`SessionCipher` can be used to
/// encrypt/decrypt messages in that session.
///
/// Sessions are built from one of three different possible vectors:
///
/// 1. A `PreKeyBundle` retrieved from a server.
/// 2. A `PreKeySignalMessage` received from a client.
/// 3. A `KeyExchangeMessages` Two clients can exchange KeyExchange messages to
/// establish a session.
///
/// Sessions are constructed per `recipient_id` + `device_id`
/// tuple.
///
/// Remote logical users are identified by their `recipient_id`, and each
/// logical `recipient_id` can have multiple physical devices.
pub struct SessionBuilder {}

/// The main entry point for Signal Protocol encrypt/decrypt operations.
///
/// Once a session has been established with `SessionBuilder`,
/// this helper can be used for all encrypt/decrypt operations within
/// that session.
pub struct SessionCipher {}
