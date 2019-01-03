use crate::error::SignalError;
use getset::Getters;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const DERIVED_MESSAGE_SECRETS_SIZE: u8 = 80;
pub const DERIVED_ROOT_SECRETS_SIZE: u8 = 64;
const DERIVED_MESSAGE_SECRETS_CIPHER_KEY_LENGTH: u8 = 32;
const DERIVED_MESSAGE_SECRETS_MAC_KEY_LENGTH: u8 = 32;
const DERIVED_MESSAGE_SECRETS_IV_LENGTH: u8 = 16;
const HKDF_HASH_OUTPUT_SIZE: u8 = 32;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Default, PartialEq, Eq, Getters)]
pub struct DerivedRootSecrets {
  #[get = "pub"]
  root_key: Vec<u8>,
  #[get = "pub"]
  chain_key: Vec<u8>,
}

impl DerivedRootSecrets {
  pub fn new(okm: &[u8]) -> Result<Self, SignalError> {
    let len = (DERIVED_ROOT_SECRETS_SIZE / 2) as usize;
    if okm.len() < len {
      return Err(SignalError::BufferTooSmall(
        DERIVED_ROOT_SECRETS_SIZE as usize,
      ));
    }
    let (root_key, chain_key) = (&okm[0..len], &okm[len..len * 2]);
    Ok(Self {
      root_key: root_key.to_vec(),
      chain_key: chain_key.to_vec(),
    })
  }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Getters)]
pub struct DerivedMessageSecrets {
  /// AES Key
  #[get = "pub"]
  cipher_key: Vec<u8>,
  /// HMAC with SHA256 Key
  #[get = "pub"]
  mac_key: Vec<u8>,
  #[get = "pub"]
  iv: Vec<u8>,
}

impl DerivedMessageSecrets {
  pub fn new(okm: &[u8]) -> Result<Self, SignalError> {
    let total_len = (DERIVED_MESSAGE_SECRETS_CIPHER_KEY_LENGTH
      + DERIVED_MESSAGE_SECRETS_MAC_KEY_LENGTH
      + DERIVED_MESSAGE_SECRETS_IV_LENGTH) as usize;
    if okm.len() < total_len {
      return Err(SignalError::BufferTooSmall(
        DERIVED_ROOT_SECRETS_SIZE as usize,
      ));
    }
    let c_len = DERIVED_MESSAGE_SECRETS_CIPHER_KEY_LENGTH as usize;
    let m_len = DERIVED_MESSAGE_SECRETS_MAC_KEY_LENGTH as usize;
    let iv_len = DERIVED_MESSAGE_SECRETS_IV_LENGTH as usize;
    let (cipher_key, mac_key, iv) = (
      &okm[0..c_len],
      &okm[c_len..(c_len + m_len)],
      &okm[(c_len + m_len)..(c_len + m_len + iv_len)],
    );
    Ok(Self {
      cipher_key: cipher_key.to_vec(),
      mac_key: mac_key.to_vec(),
      iv: iv.to_vec(),
    })
  }
}

pub trait HKDF {
  fn get_iteration_start_offset() -> usize;
  fn get_msg_ver(&self) -> u32;
  fn expand(prk: &[u8], info: Option<&[u8]>, out_size: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let iter_count =
      (out_size as f32 / f32::from(HKDF_HASH_OUTPUT_SIZE)).ceil() as usize;
    let mut mixin = vec![];
    let mut remaining_bytes = out_size;
    let iter_offset = Self::get_iteration_start_offset();
    for i in iter_offset..(iter_count + iter_offset) {
      let mut mac =
        HmacSha256::new_varkey(prk).expect("HMAC can take key of any size");
      mac.input(&mixin);
      if let Some(info) = info {
        mac.input(info);
      }
      let i_str = (i as u8) as char;
      let mut b = [0; 2];
      let i_bytes = i_str.encode_utf8(&mut b);
      mac.input(i_bytes.as_bytes());
      let step_result = mac.result().code();
      let step_size = usize::min(remaining_bytes, step_result.len());
      result.extend_from_slice(&step_result[..step_size]);
      mixin = step_result.to_vec();
      remaining_bytes -= step_size;
    }
    result
  }

  fn extract(salt: &[u8], input_key_material: &[u8]) -> Vec<u8> {
    let mut mac =
      HmacSha256::new_varkey(salt).expect("HMAC can take key of any size");
    mac.input(input_key_material);
    mac.result().code().to_vec()
  }

  fn derive_secrets(
    input_key_material: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    out_size: usize,
  ) -> Vec<u8> {
    let my_salt;
    if let Some(salt) = salt {
      my_salt = salt;
    } else {
      my_salt = &[0u8; HKDF_HASH_OUTPUT_SIZE as usize];
    }

    let prk = Self::extract(my_salt, input_key_material);
    Self::expand(&prk, info, out_size)
  }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HKDFv2;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HKDFv3;

impl HKDF for HKDFv2 {
  fn get_iteration_start_offset() -> usize { 0 }

  fn get_msg_ver(&self) -> u32 { 2 }
}

impl HKDF for HKDFv3 {
  fn get_iteration_start_offset() -> usize { 1 }

  fn get_msg_ver(&self) -> u32 { 3 }
}

#[cfg(test)]
mod test_kdf {
  use super::*;

  #[test]
  fn test_vector_v3() {
    let ikm = [
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    ];

    let salt = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c,
    ];

    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

    let okm = [
      0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64,
      0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
      0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
      0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    let output = HKDFv3::derive_secrets(&ikm, Some(&salt), Some(&info), 42);
    assert_eq!(output.len(), okm.len());
    assert_eq!(output, okm.to_vec());
  }

  #[test]
  fn test_vector_v3_long() {
    let ikm = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
      0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
      0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
      0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
    ];

    let salt = [
      0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
      0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
      0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
      0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
      0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
      0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
      0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    ];

    let info = [
      0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
      0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
      0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3,
      0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
      0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb,
      0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
      0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    ];

    let okm = [
      0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c,
      0x59, 0x6a, 0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
      0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99,
      0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
      0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9,
      0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
      0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
    ];

    let output = HKDFv3::derive_secrets(&ikm, Some(&salt), Some(&info), 82);
    assert_eq!(output.len(), okm.len());
    assert_eq!(output, okm.to_vec());
  }

  #[test]
  fn test_vector_v2() {
    let ikm = [
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    ];

    let salt = [
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c,
    ];

    let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

    let okm = [
      0x6e, 0xc2, 0x55, 0x6d, 0x5d, 0x7b, 0x1d, 0x81, 0xde, 0xe4, 0x22, 0x2a,
      0xd7, 0x48, 0x36, 0x95, 0xdd, 0xc9, 0x8f, 0x4f, 0x5f, 0xab, 0xc0, 0xe0,
      0x20, 0x5d, 0xc2, 0xef, 0x87, 0x52, 0xd4, 0x1e, 0x04, 0xe2, 0xe2, 0x11,
      0x01, 0xc6, 0x8f, 0xf0, 0x93, 0x94, 0xb8, 0xad, 0x0b, 0xdc, 0xb9, 0x60,
      0x9c, 0xd4, 0xee, 0x82, 0xac, 0x13, 0x19, 0x9b, 0x4a, 0xa9, 0xfd, 0xa8,
      0x99, 0xda, 0xeb, 0xec,
    ];
    let output = HKDFv2::derive_secrets(&ikm, Some(&salt), Some(&info), 64);
    assert_eq!(output.len(), okm.len());
    assert_eq!(output, okm.to_vec());
  }
}
