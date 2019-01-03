use crate::{
  ecc::{Curve, DjbECKey, ECKeyPair},
  error::SignalError,
  identity_key::{IdentityKey, IdentityKeyPair},
  state::{PreKeyRecord, SignedPreKeyRecord},
  utils,
};
use rand::{rngs::SmallRng, RngCore, SeedableRng};

const MEDIUM_MAX_VALUE: u32 = 0x00FF_FFFF;

/// Helper container for generating keys of different types.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyHelper;

impl KeyHelper {
  /// Generate an identity key pair.
  ///
  /// Clients should only do this once, at install time.
  pub fn generate_identity_key_pair() -> IdentityKeyPair<DjbECKey> {
    let key_pair: ECKeyPair<DjbECKey> = Curve::generate_key_pair();
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

  /// Generate a list of PreKeys.
  ///
  /// Clients should do this at install time, and subsequently any time the list
  /// of PreKeys stored on the server runs low.
  /// PreKey IDs are shorts, so they will eventually be repeated.
  ///
  /// Clients should store PreKeys in a circular buffer, so that they are
  /// repeated as infrequently as possible.
  ///
  /// * `start` The starting PreKey ID, inclusive.
  /// * `count` The number of PreKeys to generate.
  pub fn generate_pre_keys(start: u32, count: u32) -> Vec<PreKeyRecord> {
    let mut keys = Vec::new();
    let start = start - 1;
    for i in 0..count {
      let id = ((start + i) % (MEDIUM_MAX_VALUE - 1)) + 1;
      let key_pair = Curve::generate_key_pair();
      let pre_key = PreKeyRecord::new(id, &key_pair);
      keys.push(pre_key);
    }
    keys
  }

  /// Generate a signed PreKey
  ///
  /// * `identity_key_pair` The local client's identity key pair.
  /// * `signed_pre_key_id` The PreKey id to assign the generated signed PreKey
  pub fn generate_signed_pre_key(
    identity_key_pair: IdentityKeyPair<DjbECKey>,
    signed_pre_key_id: u32,
  ) -> Result<SignedPreKeyRecord, SignalError> {
    let key_pair = Curve::generate_key_pair();
    let signature = Curve::calculate_signature(
      identity_key_pair.private_key(),
      &identity_key_pair.public_key().serialize(),
    )?;
    let current_ts = utils::current_timestamp_ms();
    let signed_pre_key_record = SignedPreKeyRecord::new(
      signed_pre_key_id,
      current_ts,
      &key_pair,
      &signature,
    );
    Ok(signed_pre_key_record)
  }

  pub fn generate_sender_signing_key() -> ECKeyPair<DjbECKey> {
    Curve::generate_key_pair()
  }

  pub fn generate_sender_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut rng = SmallRng::seed_from_u64(16380);
    rng.fill_bytes(&mut key);
    key
  }

  pub fn generate_sender_key_id() -> u32 {
    let mut rng = SmallRng::seed_from_u64(u64::max_value() - 1);
    rng.next_u32()
  }
}
