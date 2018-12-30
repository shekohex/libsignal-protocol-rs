use crate::{identity_key::IdentityKey, utils};
use sha2::digest::Digest;
const VERSION: &[u8] = b"DeviceConsistencyCommitment_V0";
const CODE_VERSION: u16 = 0;

#[derive(Copy, Clone, Debug, Default, Eq, Ord, PartialOrd, Hash)]
pub struct DeviceConsistencySignature<'a> {
  signature: &'a [u8],
  vrf_output: &'a [u8],
}

impl<'a> DeviceConsistencySignature<'a> {
  pub fn new(signature: &'a [u8], vrf_output: &'a [u8]) -> Self {
    Self {
      signature,
      vrf_output,
    }
  }

  pub fn get_signature(&self) -> &'a [u8] { &self.signature }

  pub fn get_vrf_output(&self) -> &'a [u8] { &self.vrf_output }
}

pub struct DeviceConsistencyCommitment {
  generation: u32,
  serialized: Vec<u8>,
}

impl DeviceConsistencyCommitment {
  pub fn new(generation: u32, mut identity_keys: Vec<IdentityKey>) -> Self {
    identity_keys.sort(); // sort it
    let mut msg_digest = sha2::Sha512::default();
    msg_digest.input(VERSION);
    let bytes: [u8; 4] = unsafe { std::mem::transmute(generation.to_be()) };
    msg_digest.input(bytes);
    for commitment in identity_keys {
      msg_digest.input(commitment.serialize());
    }
    Self {
      generation,
      serialized: msg_digest.result().to_vec(),
    }
  }

  pub fn into_bytes(self) -> Vec<u8> { self.serialized }

  pub fn as_bytes(&self) -> &[u8] { &self.serialized }

  pub fn get_generation(&self) -> u32 { self.generation }
}

pub struct DeviceConsistencyCodeGenerator;

impl DeviceConsistencyCodeGenerator {
  pub fn generate_for(
    commitment: &DeviceConsistencyCommitment,
    mut signatures: Vec<DeviceConsistencySignature>,
  ) -> String {
    signatures.sort();
    let mut msg_digest = sha2::Sha512::default();
    let bytes: [u8; 2] = unsafe { std::mem::transmute(CODE_VERSION.to_be()) };
    msg_digest.input(bytes);
    msg_digest.input(commitment.as_bytes());
    for signature in signatures {
      msg_digest.input(signature.get_vrf_output());
    }
    let hash = msg_digest.result().to_vec();
    let digits = Self::get_encoded_chunk(&hash, 0) + &Self::get_encoded_chunk(&hash, 5);
    digits[0..6].to_string()
  }

  fn get_encoded_chunk(chunk: &[u8], offset: usize) -> String {
    let result = utils::byte_array5_to_u64(chunk, offset) % 100_000;
    format!("{:05}", result)
  }
}

impl<'a> PartialEq for DeviceConsistencySignature<'a> {
  fn eq(&self, other: &Self) -> bool {
    self.get_vrf_output() == other.get_vrf_output()
  }
}
