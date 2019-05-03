#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use rand::{rngs::OsRng, RngCore};
use std::fmt::{self, Display};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CurveError {
  VrfSignatureVerificationFailed,
  CalculateSignatureFailed,
}

impl Display for CurveError {
  fn fmt(
    &self,
    f: &mut fmt::Formatter<'_>,
  ) -> std::result::Result<(), std::fmt::Error> {
    use crate::CurveError::*;
    match self {
      VrfSignatureVerificationFailed => write!(f, "Invalid signature"),
      CalculateSignatureFailed => {
        write!(f, "Error While Calculating the Signature")
      },
    }
  }
}

pub struct KeyPair {
  pub private_key: [u8; 32],
  pub public_key: [u8; 32],
}

pub struct Curve25519<R: RngCore> {
  provider: R,
}

impl Default for Curve25519<OsRng> {
  /// Create the `Curve25519` with `OsRng` as a provider
  ///
  /// ### Panics
  /// if it is unable to create the `OsRng`
  fn default() -> Self {
    let os_rng = OsRng::new().unwrap();
    Self::new(os_rng)
  }
}

impl<R: RngCore> Curve25519<R> {
  pub fn new(provider: R) -> Self { Self { provider } }

  /// Generates a Curve25519 keypair.
  pub fn generate_key_pair(&mut self) -> KeyPair {
    let mut private_key = [0; 32];
    let mut public_key = [0; 32];
    let mut basepoint = [0; 32];
    basepoint[0] = 9;
    self.provider.fill_bytes(&mut private_key);
    // curve25519 secret key bit manip.
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    unsafe {
      curve25519_donna(
        public_key.as_mut_ptr(),
        private_key.as_ptr(),
        basepoint.as_ptr(),
      )
    };
    KeyPair {
      private_key,
      public_key,
    }
  }

  /// Calculates an ECDH agreement.
  ///
  /// `public_key` & `private_key` must be a 32 bit long.
  ///
  /// the `public_key` is The Curve25519 (typically remote party's) public key
  /// and the `private_key` is The Curve25519 (typically yours) private key.
  ///
  /// you will get a 32-byte shared secret.
  pub fn calculate_agreement(&self, key_pair: &KeyPair) -> [u8; 32] {
    let mut shared_key = [0; 32];
    unsafe {
      curve25519_donna(
        shared_key.as_mut_ptr(),
        key_pair.private_key.as_ptr(),
        key_pair.public_key.as_ptr(),
      )
    };
    shared_key
  }

  /// Calculates a Curve25519 signature.
  ///
  /// you will need The private Curve25519 key to create the signature with.
  /// and The message to sign.
  ///
  /// and you will get a 64-byte signature.
  pub fn calculate_signature(
    &mut self,
    private_key: &[u8; 32],
    msg: &[u8],
  ) -> Result<[u8; 64], CurveError> {
    let mut signature = [0; 64];
    let mut random = [0; 64];
    self.provider.fill_bytes(&mut random);
    let result = unsafe {
      xed25519_sign(
        signature.as_mut_ptr(),
        private_key.as_ptr(),
        msg.as_ptr(),
        msg.len() as u64,
        random.as_ptr(),
      )
    };

    if result == 0 {
      Ok(signature)
    } else {
      Err(CurveError::CalculateSignatureFailed)
    }
  }

  /// Verify a Curve25519 signature.
  pub fn verify_signature(
    &self,
    public_key: &[u8; 32],
    msg: &[u8],
    signature: &[u8; 64],
  ) -> bool {
    unsafe {
      curve25519_verify(
        signature.as_ptr(),
        public_key.as_ptr(),
        msg.as_ptr(),
        msg.len() as u64,
      ) == 0
    }
  }

  /// Calculates a Unique Curve25519 signature.
  pub fn calculate_vrf_signature(
    &mut self,
    private_key: &[u8; 32],
    msg: &[u8],
  ) -> Result<[u8; 96], CurveError> {
    let mut signature = [0; 96];
    let mut random = [0; 64];
    self.provider.fill_bytes(&mut random);
    let result = unsafe {
      generalized_xveddsa_25519_sign(
        signature.as_mut_ptr(),
        private_key.as_ptr(),
        msg.as_ptr(),
        msg.len() as u64,
        random.as_ptr(),
        std::ptr::null(),
        0,
      )
    };

    if result == 0 {
      Ok(signature)
    } else {
      Err(CurveError::CalculateSignatureFailed)
    }
  }

  /// Verify a Unique Curve25519 signature.
  pub fn verify_vrf_signature(
    &self,
    public_key: &[u8; 32],
    msg: &[u8],
    signature: &[u8; 96],
  ) -> Result<[u8; 32], CurveError> {
    let mut vrf = [0; 32];
    let result = unsafe {
      generalized_xveddsa_25519_verify(
        vrf.as_mut_ptr(),
        signature.as_ptr(),
        public_key.as_ptr(),
        msg.as_ptr(),
        msg.len() as u64,
        std::ptr::null(),
        0,
      )
    };
    if result == 0 {
      Ok(vrf)
    } else {
      Err(CurveError::VrfSignatureVerificationFailed)
    }
  }
}

#[cfg(test)]
mod test_curve25519_bindgen {
  use super::*;

  #[test]
  fn test_curvesigs() {
    let signature_correct: [u8; 64] = [
      0xcf, 0x87, 0x3d, 0x03, 0x79, 0xac, 0x20, 0xe8, 0x89, 0x3e, 0x55, 0x67,
      0xee, 0x0f, 0x89, 0x51, 0xf8, 0xdb, 0x84, 0x0d, 0x26, 0xb2, 0x43, 0xb4,
      0x63, 0x52, 0x66, 0x89, 0xd0, 0x1c, 0xa7, 0x18, 0xac, 0x18, 0x9f, 0xb1,
      0x67, 0x85, 0x74, 0xeb, 0xdd, 0xe5, 0x69, 0x33, 0x06, 0x59, 0x44, 0x8b,
      0x0b, 0xd6, 0xc1, 0x97, 0x3f, 0x7d, 0x78, 0x0a, 0xb3, 0x95, 0x18, 0x62,
      0x68, 0x03, 0xd7, 0x82,
    ];
    let mut privkey = [0; 32];
    let mut pubkey = [0; 32];
    let mut signature = [0; 64];
    let msg = [0; 200];
    let random = [0; 64];
    privkey[8] = 189; // just so there's some bits set
    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;

    unsafe {
      // Signature vector test
      curve25519_keygen(pubkey.as_mut_ptr(), privkey.as_ptr());
      curve25519_sign(
        signature.as_mut_ptr(),
        privkey.as_ptr(),
        msg.as_ptr(),
        200,
        random.as_ptr(),
      );
      assert_eq!(signature.to_vec(), signature_correct.to_vec());
      // Curvesig verify #1
      let result = curve25519_verify(
        signature.as_ptr(),
        pubkey.as_ptr(),
        msg.as_ptr(),
        200,
      );
      assert_eq!(result, 0);
      signature[0] ^= 1;
      // Curvesig verify #2
      let result = curve25519_verify(
        signature.as_ptr(),
        pubkey.as_ptr(),
        msg.as_ptr(),
        200,
      );
      assert_ne!(result, 0);
    }
  }

  #[test]
  fn test_xeddsa() {
    let signature_correct: [u8; 64] = [
      0x11, 0xc7, 0xf3, 0xe6, 0xc4, 0xdf, 0x9e, 0x8a, 0x51, 0x50, 0xe1, 0xdb,
      0x3b, 0x30, 0xf9, 0x2d, 0xe3, 0xa3, 0xb3, 0xaa, 0x43, 0x86, 0x56, 0x54,
      0x5f, 0xa7, 0x39, 0x0f, 0x4b, 0xcc, 0x7b, 0xb2, 0x6c, 0x43, 0x1d, 0x9e,
      0x90, 0x64, 0x3e, 0x4f, 0x0e, 0xaa, 0x0e, 0x9c, 0x55, 0x77, 0x66, 0xfa,
      0x69, 0xad, 0xa5, 0x76, 0xd6, 0x3d, 0xca, 0xf2, 0xac, 0x32, 0x6c, 0x11,
      0xd0, 0xb9, 0x77, 0x02,
    ];
    let mut privkey = [0; 32];
    let mut pubkey = [0; 32];
    let mut signature = [0; 64];
    let msg = [0; 200];
    let random = [0; 64];
    privkey[8] = 189; // just so there's some bits set
    privkey[0] &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;

    unsafe {
      // Signature vector test
      curve25519_keygen(pubkey.as_mut_ptr(), privkey.as_ptr());
      xed25519_sign(
        signature.as_mut_ptr(),
        privkey.as_ptr(),
        msg.as_ptr(),
        200,
        random.as_ptr(),
      );
      assert_eq!(signature.to_vec(), signature_correct.to_vec());
      // XEdDSA verify #1
      let result =
        xed25519_verify(signature.as_ptr(), pubkey.as_ptr(), msg.as_ptr(), 200);
      assert_eq!(result, 0);
      signature[0] ^= 1;
      // XEdDSA verify #2
      let result =
        xed25519_verify(signature.as_ptr(), pubkey.as_ptr(), msg.as_ptr(), 200);
      assert_ne!(result, 0);

      let pubkey = [0xFF; 32];
      // XEdDSA verify #3
      let result =
        xed25519_verify(signature.as_ptr(), pubkey.as_ptr(), msg.as_ptr(), 200);
      assert_ne!(result, 0);
    }
  }
}
