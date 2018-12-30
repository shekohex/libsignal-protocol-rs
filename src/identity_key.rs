use crate::{
  ecc::{Curve, ECKey},
  error::SignalError,
  utils::ToHex,
};
use core::cmp::Ordering;
use std::hash::{Hash, Hasher};

pub struct IdentityKey {
  public_key: Box<dyn ECKey>,
}

impl IdentityKey {
  pub fn new(public_key: Box<dyn ECKey>) -> Self { Self { public_key } }

  pub fn from_raw(bytes: &[u8], offset: usize) -> Result<Self, SignalError> {
    let key = Curve::decode_point(bytes, offset)?;
    Ok(Self {
      public_key: Box::new(key),
    })
  }

  pub fn get_public_key(&self) -> &dyn ECKey { self.public_key.as_ref() }

  pub fn serialize(&self) -> Vec<u8> { self.public_key.serialize() }

  pub fn get_fingerprint(&self) -> String { self.serialize().to_hex() }
}

impl Hash for IdentityKey {
  fn hash<H: Hasher>(&self, state: &mut H) { self.serialize().hash(state); }
}

impl PartialEq for IdentityKey {
  fn eq(&self, other: &Self) -> bool { self.serialize() == other.serialize() }
}

impl Eq for IdentityKey {}

impl PartialOrd for IdentityKey {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    self.serialize().partial_cmp(&other.serialize())
  }
}

impl Ord for IdentityKey {
  fn cmp(&self, other: &Self) -> Ordering {
    self.serialize().cmp(&other.serialize())
  }
}
