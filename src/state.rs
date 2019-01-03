use crate::{
  ecc::{Curve, DjbECKey, ECKey, ECKeyPair},
  error::SignalError,
  protos::textsecure::{PreKeyRecordStructure, SignedPreKeyRecordStructure},
};
use prost::Message;

pub struct PreKeyRecord {
  structure: PreKeyRecordStructure,
}

impl PreKeyRecord {
  pub fn new(id: u32, key_pair: &ECKeyPair<DjbECKey>) -> Self {
    let mut structure = PreKeyRecordStructure::default();
    structure.id = Some(id);
    structure.public_key = Some(key_pair.public_key().serialize());
    structure.private_key = Some(key_pair.private_key().serialize());
    Self { structure }
  }

  pub fn from_raw(serialized: &[u8]) -> Result<Self, SignalError> {
    let structure = PreKeyRecordStructure::decode(serialized)
      .map_err(|e| SignalError::ProtoBufError(e.to_string()))?;
    Ok(Self { structure })
  }

  pub fn id(&self) -> Option<u32> { self.structure.id }

  pub fn key_pair(&self) -> Result<ECKeyPair<DjbECKey>, SignalError> {
    let public_key = self.structure.public_key.clone().ok_or_else(|| {
      SignalError::InvalidKey("Missing PublicKey".to_string())
    })?;
    let private_key = self.structure.private_key.clone().ok_or_else(|| {
      SignalError::InvalidKey("Missing PrivateKey".to_string())
    })?;
    let pub_key = Curve::decode_point(&public_key, 0)?;
    let prv_key = Curve::decode_private_point(&private_key);
    Ok(ECKeyPair::new(pub_key, prv_key))
  }

  pub fn serialize(&self) -> Result<Vec<u8>, SignalError> {
    let mut result = Vec::new();
    self
      .structure
      .encode(&mut result)
      .map_err(|e| SignalError::ProtoBufError(e.to_string()))?;
    Ok(result)
  }
}

pub struct SignedPreKeyRecord {
  structure: SignedPreKeyRecordStructure,
}

impl SignedPreKeyRecord {
  pub fn new(
    id: u32,
    timestamp: u64,
    key_pair: &ECKeyPair<DjbECKey>,
    signature: &[u8],
  ) -> Self {
    let mut structure = SignedPreKeyRecordStructure::default();
    structure.id = Some(id);
    structure.public_key = Some(key_pair.public_key().serialize());
    structure.private_key = Some(key_pair.private_key().serialize());
    structure.signature = Some(signature.to_vec());
    structure.timestamp = Some(timestamp);
    Self { structure }
  }

  pub fn from_raw(serialized: &[u8]) -> Result<Self, SignalError> {
    let structure = SignedPreKeyRecordStructure::decode(serialized)
      .map_err(|e| SignalError::ProtoBufError(e.to_string()))?;
    Ok(Self { structure })
  }

  pub fn id(&self) -> Option<u32> { self.structure.id }

  pub fn timestamp(&self) -> Option<u64> { self.structure.timestamp }

  pub fn signature(&self) -> &Option<Vec<u8>> { &self.structure.signature }

  pub fn key_pair(&self) -> Result<ECKeyPair<DjbECKey>, SignalError> {
    let public_key = self.structure.public_key.clone().ok_or_else(|| {
      SignalError::InvalidKey("Missing PublicKey".to_string())
    })?;
    let private_key = self.structure.private_key.clone().ok_or_else(|| {
      SignalError::InvalidKey("Missing PrivateKey".to_string())
    })?;
    let pub_key = Curve::decode_point(&public_key, 0)?;
    let prv_key = Curve::decode_private_point(&private_key);
    Ok(ECKeyPair::new(pub_key, prv_key))
  }

  pub fn serialize(&self) -> Result<Vec<u8>, SignalError> {
    let mut result = Vec::new();
    self
      .structure
      .encode(&mut result)
      .map_err(|e| SignalError::ProtoBufError(e.to_string()))?;
    Ok(result)
  }
}
