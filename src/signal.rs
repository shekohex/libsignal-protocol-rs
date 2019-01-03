use getset::Getters;
use std::fmt::{self, Display};
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
