use std::cmp::Ordering;

use getset::Getters;
use prost::Message;
use sha2::digest::Digest;

use crate::{
    ecc::{Curve, DjbECKey, ECKey},
    error::SignalError,
    identity_key::{IdentityKey, IdentityKeyPair},
    protos::textsecure,
    utils,
};

const VERSION: &[u8] = b"DeviceConsistencyCommitment_V0";
const CODE_VERSION: u16 = 0;

#[derive(Copy, Clone, Getters)]
pub struct DeviceConsistencySignature {
  #[get = "pub"]
  signature: [u8; 96],
  #[get = "pub"]
  vrf_output: [u8; 32],
}

impl DeviceConsistencySignature {
  pub fn new(signature: [u8; 96], vrf_output: [u8; 32]) -> Self {
    Self {
      signature,
      vrf_output,
    }
  }
}

impl PartialEq for DeviceConsistencySignature {
  fn eq(&self, other: &Self) -> bool {
    self.vrf_output().to_vec() == other.vrf_output().to_vec()
  }
}

impl Eq for DeviceConsistencySignature {}

impl PartialOrd for DeviceConsistencySignature {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    self
      .vrf_output
      .to_vec()
      .partial_cmp(&other.vrf_output.to_vec())
  }
}

impl Ord for DeviceConsistencySignature {
  fn cmp(&self, other: &Self) -> Ordering {
    self.vrf_output.to_vec().cmp(&other.vrf_output.to_vec())
  }
}

#[derive(Getters, Debug)]
pub struct DeviceConsistencyCommitment {
  #[get = "pub"]
  generation: u32,
  #[get = "pub"]
  serialized: Vec<u8>,
}

impl DeviceConsistencyCommitment {
  pub fn new<K: ECKey>(
    generation: u32,
    identity_keys: &mut [&IdentityKey<K>],
  ) -> Self {
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
}

pub struct DeviceConsistencyCodeGenerator;

impl DeviceConsistencyCodeGenerator {
  pub fn generate_for(
    commitment: &DeviceConsistencyCommitment,
    signatures: &mut [&DeviceConsistencySignature],
  ) -> String {
    signatures.sort();
    let mut msg_digest = sha2::Sha512::default();
    let bytes: [u8; 2] = unsafe { std::mem::transmute(CODE_VERSION.to_be()) };
    msg_digest.input(bytes);
    msg_digest.input(commitment.as_bytes());
    for signature in signatures {
      msg_digest.input(signature.vrf_output());
    }
    let hash = msg_digest.result().to_vec();
    let digits =
      Self::get_encoded_chunk(&hash, 0) + &Self::get_encoded_chunk(&hash, 5);
    digits[0..6].to_string()
  }

  fn get_encoded_chunk(chunk: &[u8], offset: usize) -> String {
    let result = utils::byte_array5_to_u64(chunk, offset) % 100_000;
    format!("{:05}", result)
  }
}

#[derive(Getters)]
pub struct DeviceConsistencyMessage {
  #[get = "pub"]
  signature: DeviceConsistencySignature,
  #[get = "pub"]
  generation: u32,
  #[get = "pub"]
  serialized: Vec<u8>,
}

impl DeviceConsistencyMessage {
  pub fn new(
    commitment: &DeviceConsistencyCommitment,
    identity_key_pair: &IdentityKeyPair<DjbECKey>,
  ) -> Result<Self, SignalError> {
    let signature_bytes = Curve::calculate_vrf_signature(
      identity_key_pair.private_key(),
      commitment.as_bytes(),
    )?;
    let vrf_output_bytes = Curve::verify_vrf_signature(
      identity_key_pair.public_key().public_key(),
      commitment.as_bytes(),
      &signature_bytes,
    )?;
    let generation = commitment.generation();
    let signature =
      DeviceConsistencySignature::new(signature_bytes, vrf_output_bytes);

    let mut device_consistency_code_message =
      textsecure::DeviceConsistencyCodeMessage::default();
    device_consistency_code_message.generation = Some(*generation);
    device_consistency_code_message.signature =
      Some(signature.signature().to_vec());
    let mut serialized = Vec::new();
    device_consistency_code_message
      .encode(&mut serialized)
      .map_err(|e| SignalError::ProtoBufError(e.to_string()))?;
    Ok(Self {
      signature,
      generation: *generation,
      serialized,
    })
  }

  pub fn from_serialized(
    commitment: &DeviceConsistencyCommitment,
    identity_pair: &IdentityKey<DjbECKey>,
    serialized: &[u8],
  ) -> Result<Self, SignalError> {
    let device_consistency_code_message =
      textsecure::DeviceConsistencyCodeMessage::decode(serialized)
        .map_err(|e| SignalError::ProtoBufError(e.to_string()))?;
    let signature_bytes = device_consistency_code_message
      .signature
      .ok_or_else(|| SignalError::ProtoBufError("Missing signature".into()))?;
    let mut array = [0; 96];
    let bytes = &signature_bytes[..96]; // panics if not enough data
    array.copy_from_slice(bytes);
    let vrf_output_bytes = Curve::verify_vrf_signature(
      identity_pair.public_key(),
      commitment.as_bytes(),
      &array,
    )?;
    let generation = device_consistency_code_message
      .generation
      .ok_or_else(|| SignalError::ProtoBufError("Missing generation".into()))?;
    let signature = DeviceConsistencySignature::new(array, vrf_output_bytes);
    let mut serialized_bytes = vec![0; serialized.len()];
    serialized_bytes.copy_from_slice(&serialized);
    Ok(Self {
      generation,
      serialized: serialized_bytes,
      signature,
    })
  }
}

#[cfg(test)]
mod test_devices {
    use crate::key_helper::KeyHelper;

    use super::*;

    fn generate_code(
    commitment: &DeviceConsistencyCommitment,
    messages: &[&DeviceConsistencyMessage],
  ) -> String {
    let mut signatures: Vec<_> =
      messages.iter().map(|m| m.signature()).collect();
    DeviceConsistencyCodeGenerator::generate_for(commitment, &mut signatures)
  }

  #[test]
  fn test_device_consistency() {
    let device_one = KeyHelper::generate_identity_key_pair();
    let device_two = KeyHelper::generate_identity_key_pair();
    let device_three = KeyHelper::generate_identity_key_pair();

    let mut keys = vec![
      device_one.public_key(),
      device_two.public_key(),
      device_three.public_key(),
    ];
    keys.rotate_left(2); // act as shuffle;
    let device_one_commitment =
      DeviceConsistencyCommitment::new(1, keys.as_mut_slice());
    keys.rotate_left(1); // act as shuffle;
    let device_two_commitment =
      DeviceConsistencyCommitment::new(1, keys.as_mut_slice());
    keys.rotate_left(2); // act as shuffle;
    let device_three_commitment =
      DeviceConsistencyCommitment::new(1, keys.as_mut_slice());
    assert_eq!(
      device_one_commitment.as_bytes(),
      device_two_commitment.as_bytes()
    );
    assert_eq!(
      device_two_commitment.as_bytes(),
      device_three_commitment.as_bytes()
    );

    let device_one_msg =
      DeviceConsistencyMessage::new(&device_one_commitment, &device_one)
        .unwrap();
    let device_two_msg =
      DeviceConsistencyMessage::new(&device_one_commitment, &device_two)
        .unwrap();
    let device_three_msg =
      DeviceConsistencyMessage::new(&device_one_commitment, &device_three)
        .unwrap();
    let received_device_one_message =
      DeviceConsistencyMessage::from_serialized(
        &device_one_commitment,
        &device_one.public_key(),
        device_one_msg.serialized(),
      )
      .unwrap();
    let received_device_two_message =
      DeviceConsistencyMessage::from_serialized(
        &device_one_commitment,
        &device_two.public_key(),
        device_two_msg.serialized(),
      )
      .unwrap();
    let received_device_three_message =
      DeviceConsistencyMessage::from_serialized(
        &device_one_commitment,
        &device_three.public_key(),
        device_three_msg.serialized(),
      )
      .unwrap();

    assert_eq!(
      device_one_msg.signature().vrf_output(),
      received_device_one_message.signature().vrf_output()
    );

    assert_eq!(
      device_two_msg.signature().vrf_output(),
      received_device_two_message.signature().vrf_output()
    );

    assert_eq!(
      device_three_msg.signature().vrf_output(),
      received_device_three_message.signature().vrf_output()
    );

    let code_one = generate_code(
      &device_one_commitment,
      &[
        &device_one_msg,
        &received_device_two_message,
        &received_device_three_message,
      ],
    );

    let code_two = generate_code(
      &device_two_commitment,
      &[
        &device_two_msg,
        &received_device_three_message,
        &received_device_one_message,
      ],
    );

    let code_three = generate_code(
      &device_three_commitment,
      &[
        &device_three_msg,
        &received_device_two_message,
        &received_device_one_message,
      ],
    );

    assert_eq!(code_one, code_two);
    assert_eq!(code_two, code_three);
  }
}
