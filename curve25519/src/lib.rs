#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod test_curve25519 {
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
      let result = xed25519_verify(
        signature.as_ptr(),
        pubkey.as_ptr(),
        msg.as_ptr(),
        200,
      );
      assert_eq!(result, 0);
      signature[0] ^= 1;
      // XEdDSA verify #2
      let result = xed25519_verify(
        signature.as_ptr(),
        pubkey.as_ptr(),
        msg.as_ptr(),
        200,
      );
      assert_ne!(result, 0);

      let pubkey = [0xFF; 32];
      // XEdDSA verify #3
      let result = xed25519_verify(
        signature.as_ptr(),
        pubkey.as_ptr(),
        msg.as_ptr(),
        200,
      );
      assert_ne!(result, 0);
    }
  }
}
