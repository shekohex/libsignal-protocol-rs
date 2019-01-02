use crate::error::SignalError;
use curve25519::{Curve25519, KeyPair};
use getset::Getters;

const DJB_TYPE: u8 = 0x05;

pub trait ECKey {
  fn serialize(&self) -> Vec<u8>;
  fn get_type(&self) -> u8;
  fn get_key(&self) -> Vec<u8>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Getters)]
pub struct ECKeyPair<K: ECKey> {
  #[get = "pub"]
  private_key: K,
  #[get = "pub"]
  public_key: K,
}

impl<K: ECKey> ECKeyPair<K> {
  pub fn new(public_key: K, private_key: K) -> Self {
    Self {
      private_key,
      public_key,
    }
  }

  pub fn into_public_key(self) -> K { self.public_key }

  pub fn into_private_key(self) -> K { self.private_key }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Getters)]
pub struct DjbECKey {
  #[get = "pub"]
  key: Vec<u8>,

  #[get = "pub"]
  is_private: bool,
}

impl DjbECKey {
  pub fn new(key: Vec<u8>, is_private: bool) -> Self {
    Self { key, is_private }
  }
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

  fn get_key(&self) -> Vec<u8> { self.key.clone() }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Curve;

impl Curve {
  pub fn generate_key_pair() -> ECKeyPair<DjbECKey> {
    let mut curve25519 = Curve25519::default();
    let key_pair = curve25519.generate_key_pair();
    ECKeyPair::new(
      DjbECKey::new(key_pair.public_key.to_vec(), false),
      DjbECKey::new(key_pair.private_key.to_vec(), true),
    )
  }

  pub fn decode_point(
    bytes: &[u8],
    offset: usize,
  ) -> Result<DjbECKey, SignalError> {
    if bytes.len() - offset < 1 {
      return Err(SignalError::InvalidKey(
        "No key type identifier or bad offset".to_string(),
      ));
    }
    let k_type = bytes[offset]; // & 0xFF clippy says that ineffective
    match k_type {
      DJB_TYPE => {
        if bytes.len() - offset < 33 {
          Err(SignalError::InvalidKey("Bad key length".to_string()))
        } else {
          let mut key_bytes = [0; 32];
          let len = key_bytes.len() + offset;
          key_bytes.copy_from_slice(&bytes[(offset + 1)..=len]);
          Ok(DjbECKey::new(key_bytes.to_vec(), false))
        }
      },
      _ => Err(SignalError::InvalidKey("Bad key type".to_string())),
    }
  }

  pub fn decode_private_point(bytes: &[u8]) -> DjbECKey {
    DjbECKey::new(bytes.to_vec(), true)
  }

  pub fn calculate_agreement(
    public_key: &impl ECKey,
    private_key: &impl ECKey,
  ) -> Result<[u8; 32], SignalError> {
    if public_key.get_type() != private_key.get_type() {
      Err(SignalError::InvalidKey(
        "Public and private keys must be of the same type!".to_string(),
      ))
    } else if public_key.get_type() != DJB_TYPE {
      Err(SignalError::InvalidKey("Unknown key type".to_string()))
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
    signing_key: &impl ECKey,
    message: &[u8],
    signature: &[u8; 64],
  ) -> Result<bool, SignalError> {
    if signing_key.get_type() == DJB_TYPE {
      let curve25519 = Curve25519::default();
      let pub_key = Self::key_from_vec(signing_key);
      let result = curve25519.verify_signature(&pub_key, message, signature);
      Ok(result)
    } else {
      Err(SignalError::InvalidKey("Unknown Key type".to_string()))
    }
  }

  pub fn calculate_signature(
    signing_key: impl ECKey,
    message: &[u8],
  ) -> Result<[u8; 64], SignalError> {
    if signing_key.get_type() != DJB_TYPE {
      let mut curve25519 = Curve25519::default();
      let prv_key = Self::key_from_vec(&signing_key);
      let result = curve25519
        .calculate_signature(&prv_key, message)
        .map_err(|_| SignalError::SignatureFailure)?;
      Ok(result)
    } else {
      Err(SignalError::InvalidKey("Unknown Key type".to_string()))
    }
  }

  pub fn verify_vrf_signature(
    signing_key: impl ECKey,
    message: &[u8],
    signature: &[u8; 96],
  ) -> Result<[u8; 32], SignalError> {
    if signing_key.get_type() != DJB_TYPE {
      let curve25519 = Curve25519::default();
      let pub_key = Self::key_from_vec(&signing_key);
      let result = curve25519
        .verify_vrf_signature(&pub_key, message, signature)
        .map_err(|_| SignalError::SignatureFailure)?;
      Ok(result)
    } else {
      Err(SignalError::InvalidKey("Unknown Key type".to_string()))
    }
  }

  pub fn calculate_vrf_signature(
    signing_key: impl ECKey,
    message: &[u8],
  ) -> Result<[u8; 96], SignalError> {
    if signing_key.get_type() != DJB_TYPE {
      let mut curve25519 = Curve25519::default();
      let prv_key = Self::key_from_vec(&signing_key);
      let result = curve25519
        .calculate_vrf_signature(&prv_key, message)
        .map_err(|_| SignalError::SignatureFailure)?;
      Ok(result)
    } else {
      Err(SignalError::InvalidKey("Unknown Key type".to_string()))
    }
  }

  fn key_from_vec(eckey: &impl ECKey) -> [u8; 32] {
    let key = eckey.get_key();
    let mut array = [0; 32];
    let bytes = &key[..32]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
  }
}

#[cfg(test)]
mod test_curve25519 {
  use super::*;

  #[test]
  fn test_agreement() {
    let alice_public = [
      0x05, 0x1b, 0xb7, 0x59, 0x66, 0xf2, 0xe9, 0x3a, 0x36, 0x91, 0xdf, 0xff,
      0x94, 0x2b, 0xb2, 0xa4, 0x66, 0xa1, 0xc0, 0x8b, 0x8d, 0x78, 0xca, 0x3f,
      0x4d, 0x6d, 0xf8, 0xb8, 0xbf, 0xa2, 0xe4, 0xee, 0x28,
    ];
    let alice_private = [
      0xc8, 0x06, 0x43, 0x9d, 0xc9, 0xd2, 0xc4, 0x76, 0xff, 0xed, 0x8f, 0x25,
      0x80, 0xc0, 0x88, 0x8d, 0x58, 0xab, 0x40, 0x6b, 0xf7, 0xae, 0x36, 0x98,
      0x87, 0x90, 0x21, 0xb9, 0x6b, 0xb4, 0xbf, 0x59,
    ];
    let bob_public = [
      0x05, 0x65, 0x36, 0x14, 0x99, 0x3d, 0x2b, 0x15, 0xee, 0x9e, 0x5f, 0xd3,
      0xd8, 0x6c, 0xe7, 0x19, 0xef, 0x4e, 0xc1, 0xda, 0xae, 0x18, 0x86, 0xa8,
      0x7b, 0x3f, 0x5f, 0xa9, 0x56, 0x5a, 0x27, 0xa2, 0x2f,
    ];
    let bob_private = [
      0xb0, 0x3b, 0x34, 0xc3, 0x3a, 0x1c, 0x44, 0xf2, 0x25, 0xb6, 0x62, 0xd2,
      0xbf, 0x48, 0x59, 0xb8, 0x13, 0x54, 0x11, 0xfa, 0x7b, 0x03, 0x86, 0xd4,
      0x5f, 0xb7, 0x5d, 0xc5, 0xb9, 0x1b, 0x44, 0x66,
    ];
    let shared = [
      0x32, 0x5f, 0x23, 0x93, 0x28, 0x94, 0x1c, 0xed, 0x6e, 0x67, 0x3b, 0x86,
      0xba, 0x41, 0x01, 0x74, 0x48, 0xe9, 0x9b, 0x64, 0x9a, 0x9c, 0x38, 0x06,
      0xc1, 0xdd, 0x7c, 0xa4, 0xc4, 0x77, 0xe6, 0x29,
    ];

    let alice_public_key = Curve::decode_point(&alice_public, 0).unwrap();
    let alice_private_key = Curve::decode_private_point(&alice_private);

    let bob_public_key = Curve::decode_point(&bob_public, 0).unwrap();
    let bob_private_key = Curve::decode_private_point(&bob_private);

    let shared1 =
      Curve::calculate_agreement(&alice_public_key, &bob_private_key).unwrap();
    let shared2 =
      Curve::calculate_agreement(&bob_public_key, &alice_private_key).unwrap();
    assert_eq!(shared1, shared);
    assert_eq!(shared2, shared);
  }
  #[test]
  fn test_random_agreements() {
    for _ in 0..50 {
      let alice = Curve::generate_key_pair();
      let bob = Curve::generate_key_pair();
      let shared_alice = Curve::calculate_agreement(
        bob.public_key(),
        alice.private_key(),
      )
      .unwrap();
      let shared_bob = Curve::calculate_agreement(
        alice.public_key(),
        bob.private_key(),
      )
      .unwrap();
      assert_eq!(shared_alice, shared_bob);
    }
  }

  #[test]
  fn test_signature() {
    let alice_identity_public = [
      0x05, 0xab, 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d, 0x9a, 0x1d, 0x80,
      0x71, 0xdf, 0xe9, 0xdc, 0xf8, 0xcd, 0xcd, 0x1c, 0xea, 0x33, 0x39, 0xb6,
      0x35, 0x6b, 0xe8, 0x4d, 0x88, 0x7e, 0x32, 0x2c, 0x64,
    ];

    let alice_ephemeral_public = [
      0x05, 0xed, 0xce, 0x9d, 0x9c, 0x41, 0x5c, 0xa7, 0x8c, 0xb7, 0x25, 0x2e,
      0x72, 0xc2, 0xc4, 0xa5, 0x54, 0xd3, 0xeb, 0x29, 0x48, 0x5a, 0x0e, 0x1d,
      0x50, 0x31, 0x18, 0xd1, 0xa8, 0x2d, 0x99, 0xfb, 0x4a,
    ];

    let alice_signature = [
      0x5d, 0xe8, 0x8c, 0xa9, 0xa8, 0x9b, 0x4a, 0x11, 0x5d, 0xa7, 0x91, 0x09,
      0xc6, 0x7c, 0x9c, 0x74, 0x64, 0xa3, 0xe4, 0x18, 0x02, 0x74, 0xf1, 0xcb,
      0x8c, 0x63, 0xc2, 0x98, 0x4e, 0x28, 0x6d, 0xfb, 0xed, 0xe8, 0x2d, 0xeb,
      0x9d, 0xcd, 0x9f, 0xae, 0x0b, 0xfb, 0xb8, 0x21, 0x56, 0x9b, 0x3d, 0x90,
      0x01, 0xbd, 0x81, 0x30, 0xcd, 0x11, 0xd4, 0x86, 0xce, 0xf0, 0x47, 0xbd,
      0x60, 0xb8, 0x6e, 0x88,
    ];

    let alice_public_key =
      Curve::decode_point(&alice_identity_public, 0).unwrap();
    let alice_ephemeral =
      Curve::decode_point(&alice_ephemeral_public, 0).unwrap();
    let verify = Curve::verify_signature(
      &alice_public_key,
      &alice_ephemeral.serialize(),
      &alice_signature,
    )
    .unwrap();
    assert!(verify);
    for i in 0..64 {
      let mut modified_signature = [0; 64];
      modified_signature.copy_from_slice(&alice_signature);
      modified_signature[i] ^= 0x01;
      let verify = Curve::verify_signature(
        &alice_public_key,
        &alice_ephemeral.serialize(),
        &modified_signature,
      )
      .unwrap();
      assert!(!verify);
    }
  }

  #[should_panic]
  #[test]
  fn test_key_too_small() {
    let key_pair = Curve::generate_key_pair();
    let serialized_public = key_pair.public_key().serialize();
    Curve::decode_point(&serialized_public, 1).unwrap();
  }

  #[should_panic]
  #[test]
  fn test_key_empty() {
    let key = [];
    Curve::decode_point(&key, 0).unwrap();
  }

  #[should_panic]
  #[test]
  fn test_bad_key_type() {
    let key_pair = Curve::generate_key_pair();
    let mut serialized_public = key_pair.public_key().serialize();
    serialized_public[0] = 0x01;
    Curve::decode_point(&serialized_public, 0).unwrap();
  }

  #[test]
  fn test_good_key() {
    let key_pair = Curve::generate_key_pair();
    let serialized_public = key_pair.public_key().serialize();
    Curve::decode_point(&serialized_public, 0).unwrap();
  }

  #[test]
  fn test_extra_key_space() {
    let key_pair = Curve::generate_key_pair();
    let serialized_public = key_pair.public_key().serialize();
    let mut extra_space_key = serialized_public[..].to_vec();
    extra_space_key.push(0);
    let result = Curve::decode_point(&extra_space_key, 0)
      .unwrap()
      .serialize();
    assert_eq!(result, serialized_public);
  }

  #[test]
  fn test_offset_key_space() {
    let key_pair = Curve::generate_key_pair();
    let serialized_public = key_pair.public_key().serialize();
    let mut offset_space_key = serialized_public.clone();
    offset_space_key.insert(0, 0);
    let result = Curve::decode_point(&offset_space_key, 1)
      .unwrap()
      .serialize();
    assert_eq!(result, serialized_public);
  }
}
