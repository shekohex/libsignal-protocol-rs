use crate::error::SignalError;
use curve25519::{Curve25519, KeyPair};

const DJB_TYPE: u8 = 0x05;

pub trait ECKey {
  fn serialize(&self) -> Vec<u8>;
  fn get_type(&self) -> u8;
}

pub struct ECKeyPair {
  private_key: Box<dyn ECKey>,
  public_key: Box<dyn ECKey>,
}

impl ECKeyPair {
  pub fn new(public_key: Box<dyn ECKey>, private_key: Box<dyn ECKey>) -> Self {
    Self {
      private_key,
      public_key,
    }
  }

  pub fn get_private_key(&self) -> &dyn ECKey { self.private_key.as_ref() }

  pub fn get_public_key(&self) -> &dyn ECKey { self.public_key.as_ref() }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DjbECKey {
  key: Vec<u8>,
  is_private: bool,
}

impl DjbECKey {
  pub fn new(key: Vec<u8>, is_private: bool) -> Self {
    Self { key, is_private }
  }

  pub fn get_key(&self) -> &[u8] { &self.key }
}

impl ECKey for DjbECKey {
  fn serialize(&self) -> Vec<u8> {
    if self.is_private {
      self.key.clone()
    } else {
      let mut result = Vec::new();
      result.push(DJB_TYPE);
      result.extend_from_slice(&self.key);
      result
    }
  }

  fn get_type(&self) -> u8 { DJB_TYPE }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Curve;

impl Curve {
  pub fn generate_key_pair() -> ECKeyPair {
    let mut curve25519 = Curve25519::default();
    let key_pair = curve25519.generate_key_pair();
    ECKeyPair::new(
      Box::new(DjbECKey::new(key_pair.public_key.to_vec(), false)),
      Box::new(DjbECKey::new(key_pair.private_key.to_vec(), true)),
    )
  }

  pub fn decode_point(
    bytes: &[u8],
    offset: usize,
  ) -> Result<impl ECKey, SignalError> {
    if bytes.len() - offset < 1 {
      return Err(SignalError::InvalidKey(
        "No key type identifier or bad offset",
      ));
    }
    let k_type = bytes[offset]; // & 0xFF clippy says that ineffective
    match k_type {
      DJB_TYPE => {
        if bytes.len() - offset < 33 {
          Err(SignalError::InvalidKey("Bad key length"))
        } else {
          let key_bytes = Vec::from(&bytes[offset + 1..]);
          Ok(DjbECKey::new(key_bytes, false))
        }
      },
      _ => Err(SignalError::InvalidKey("Bad key type")),
    }
  }

  pub fn decode_private_point(bytes: &[u8]) -> impl ECKey {
    DjbECKey::new(bytes.to_vec(), true)
  }

  pub fn calculate_agreement(
    public_key: impl ECKey,
    private_key: impl ECKey,
  ) -> Result<[u8; 32], SignalError> {
    if public_key.get_type() != private_key.get_type() {
      Err(SignalError::InvalidKey(
        "Public and private keys must be of the same type!",
      ))
    } else if public_key.get_type() != DJB_TYPE {
      Err(SignalError::InvalidKey("Unknown key type"))
    } else {
      let curve25519 = Curve25519::default();
      let pub_key = Self::key_from_vec(public_key);
      let prv_key = Self::key_from_vec(private_key);
      let key_pair = KeyPair {
        public_key: pub_key,
        private_key: prv_key,
      };
      Ok(curve25519.calculate_agreement(&key_pair))
    }
  }

  pub fn verify_signature(
    signing_key: impl ECKey,
    message: &[u8],
    signature: &[u8; 64],
  ) -> Result<bool, SignalError> {
    if signing_key.get_type() != DJB_TYPE {
      let curve25519 = Curve25519::default();
      let pub_key = Self::key_from_vec(signing_key);
      let result = curve25519.verify_signature(&pub_key, message, signature);
      Ok(result)
    } else {
      Err(SignalError::InvalidKey("Unknown Key type"))
    }
  }

  pub fn calculate_signature(
    signing_key: impl ECKey,
    message: &[u8],
  ) -> Result<[u8; 64], SignalError> {
    if signing_key.get_type() != DJB_TYPE {
      let mut curve25519 = Curve25519::default();
      let prv_key = Self::key_from_vec(signing_key);
      let result = curve25519
        .calculate_signature(&prv_key, message)
        .map_err(|_| SignalError::SignatureFailure)
        .unwrap();
      Ok(result)
    } else {
      Err(SignalError::InvalidKey("Unknown Key type"))
    }
  }

  pub fn verify_vrf_signature(
    signing_key: impl ECKey,
    message: &[u8],
    signature: &[u8; 96],
  ) -> Result<[u8; 32], SignalError> {
    if signing_key.get_type() != DJB_TYPE {
      let curve25519 = Curve25519::default();
      let pub_key = Self::key_from_vec(signing_key);
      let result = curve25519
        .verify_vrf_signature(&pub_key, message, signature)
        .map_err(|_| SignalError::SignatureFailure)
        .unwrap();
      Ok(result)
    } else {
      Err(SignalError::InvalidKey("Unknown Key type"))
    }
  }

  pub fn calculate_vrf_signature(
    signing_key: impl ECKey,
    message: &[u8],
  ) -> Result<[u8; 96], SignalError> {
    if signing_key.get_type() != DJB_TYPE {
      let mut curve25519 = Curve25519::default();
      let prv_key = Self::key_from_vec(signing_key);
      let result = curve25519
        .calculate_vrf_signature(&prv_key, message)
        .map_err(|_| SignalError::SignatureFailure)
        .unwrap();
      Ok(result)
    } else {
      Err(SignalError::InvalidKey("Unknown Key type"))
    }
  }

  fn key_from_vec(eckey: impl ECKey) -> [u8; 32] {
    let key = eckey.serialize();
    let mut array = [0; 32];
    let bytes = &key[..32]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
  }
}
