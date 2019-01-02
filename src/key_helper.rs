use crate::{
  ecc::{Curve, DjbECKey},
  identity_key::{IdentityKey, IdentityKeyPair},
};
use rand::{rngs::SmallRng, RngCore, SeedableRng};
/// Helper container for generating keys of different types.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyHelper;

impl KeyHelper {
  /// Generate an identity key pair.
  ///
  /// Clients should only do this once, at install time.
  pub fn generate_identity_key_pair() -> IdentityKeyPair<DjbECKey> {
    let key_pair = Curve::generate_key_pair();
    let public_key = IdentityKey::new(key_pair.public_key().clone());
    IdentityKeyPair::new(public_key, key_pair.private_key().clone())
  }

  /// Generate a registration ID.
  ///
  /// Clients should only do this once, at install time.
  ///
  /// if `extend_range` is `false`, the generated registration ID is sized to
  /// require the minimal possible protobuf encoding overhead. Specify `true`
  /// if the caller needs the full range of `u64::max_value()` _as a seed_ at
  /// the cost of slightly higher encoding overhead.
  pub fn generate_registration_id(extend_range: bool) -> u32 {
    let mut rng = if extend_range {
      SmallRng::seed_from_u64(u64::max_value() - 1)
    } else {
      SmallRng::seed_from_u64(16380)
    };
    rng.next_u32() + 1
  }
}
