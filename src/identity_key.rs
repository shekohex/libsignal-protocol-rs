use crate::{
  ecc::{Curve, ECKey},
  error::SignalError,
  protos::textsecure,
  utils::ToHex,
};
use core::cmp::Ordering;
use getset::Getters;
use prost::Message;
use std::hash::{Hash, Hasher};
#[derive(Clone, Debug, Getters)]
pub struct IdentityKey<E: ECKey> {
  #[get = "pub"]
  public_key: E,
}

impl<E: ECKey> IdentityKey<E> {
  pub fn new(public_key: impl ECKey) -> IdentityKey<impl ECKey> {
    IdentityKey { public_key }
  }

  pub fn serialize(&self) -> Vec<u8> { self.public_key.serialize() }

  pub fn get_fingerprint(&self) -> String { self.serialize().to_hex() }
}

impl<E: ECKey> Hash for IdentityKey<E> {
  fn hash<H: Hasher>(&self, state: &mut H) { self.serialize().hash(state); }
}

impl<E: ECKey> PartialEq for IdentityKey<E> {
  fn eq(&self, other: &Self) -> bool { self.serialize() == other.serialize() }
}

impl<E: ECKey> PartialOrd for IdentityKey<E> {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    self.serialize().partial_cmp(&other.serialize())
  }
}

impl<E: ECKey> Eq for IdentityKey<E> {}

impl<E: ECKey> Ord for IdentityKey<E> {
  fn cmp(&self, other: &Self) -> Ordering {
    self.serialize().cmp(&other.serialize())
  }
}

/// Holder for public and private identity key pair.
#[derive(Getters, Clone, Debug)]
pub struct IdentityKeyPair<E: ECKey> {
  public_key: E,
  #[get = "pub"]
  private_key: E,
}

impl<E: ECKey> IdentityKeyPair<E> {
  pub fn new(public_key: E, private_key: E) -> IdentityKeyPair<E> {
    IdentityKeyPair {
      public_key,
      private_key,
    }
  }

  pub fn from_raw(
    serialized: &[u8],
  ) -> Result<IdentityKeyPair<impl ECKey>, SignalError> {
    let structure = textsecure::IdentityKeyPairStructure::decode(serialized)
      .map_err(|e| SignalError::InvalidKey(e.to_string()))?;
    let public_key = structure.public_key.ok_or_else(|| {
      SignalError::InvalidKey("Missing PublicKey".to_string())
    })?;
    let private_key = structure.private_key.ok_or_else(|| {
      SignalError::InvalidKey("Missing PrivateKey".to_string())
    })?;
    let pub_key = Curve::decode_point(&public_key, 0)?;
    let prv_key = Curve::decode_private_point(&private_key);
    let pair = IdentityKeyPair {
      private_key: prv_key,
      public_key: pub_key,
    };
    Ok(pair)
  }

  pub fn public_key(&self) -> &IdentityKey<impl ECKey> {
    &IdentityKey::new(self.public_key)
  }
}
