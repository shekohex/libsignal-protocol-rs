use crate::{
  ecc::{Curve, DjbECKey, ECKey, ECKeyPair},
  error::SignalError,
  identity_key::{IdentityKey, IdentityKeyPair},
  protos::textsecure::{PreKeyRecordStructure, SignedPreKeyRecordStructure},
  signal::SignalProtocolAddress,
};
use prost::Message;

// const ARCHIVED_STATES_MAX_LENGTH: u8 = 40;

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

/// A `SessionRecord` encapsulates the state of an ongoing session.
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

pub struct SessionRecord {}


pub enum Direction {
  SENDING,
  RECEIVING,
}

pub trait IdentityKeyStore {
  /// Get the local client's identity key pair.
  fn get_identity_key_pair(&self) -> &IdentityKeyPair<DjbECKey>;

  /// Return the local client's registration ID.
  ///
  /// Clients should maintain a registration ID, a random number
  /// between 1 and 16380 that's generated once at install time.
  fn get_local_registration_id(&self) -> u32;

  /// Store a remote client's identity key as trusted.
  ///
  /// * `address`     The address of the remote client.
  /// * `identity_key` The remote client's identity key.
  /// should return `true` if the identity key replaces a previous identity,
  /// `false` if not
  fn save_identity(
    &mut self,
    adress: SignalProtocolAddress,
    identity_key: &IdentityKey<DjbECKey>,
  ) -> bool;

  /// Verify a remote client's identity key.
  ///
  /// Determine whether a remote client's identity is trusted.
  ///
  /// Convention is that the Signal Protocol is 'trust on first use.'  This
  /// means that an identity key is considered 'trusted' if there is no entry
  /// for the recipient in the local store, or if it matches the saved key for
  /// a recipient in the local store.  Only if it mismatches an entry in the
  /// local store is it considered 'untrusted.'
  ///
  /// Clients may wish to make a distinction as to how keys are trusted based on
  /// the direction of travel. For instance, clients may wish to accept all
  /// 'incoming' identity key changes, while only blocking identity key
  /// changes when sending a message.
  ///
  /// * `address`     The address of the remote client.
  /// * `identity_key` The identity key to verify.
  /// * `direction`   The direction (sending or receiving) this identity is
  /// being used for.
  fn is_trusted_identity(
    &self,
    adress: SignalProtocolAddress,
    identity_key: &IdentityKey<DjbECKey>,
    direction: Direction,
  ) -> bool;

  /// Return the saved public identity key for a remote client.
  ///
  /// return The public identity key, or `None` if absent
  fn get_identity(
    &self,
    adress: SignalProtocolAddress,
  ) -> Option<&IdentityKey<DjbECKey>>;
}

pub trait PreKeyStore {
  fn load_pre_key(&self, pre_key_id: u32) -> Option<&PreKeyRecord>;

  fn store_pre_key(&mut self, pre_key_id: u32, record: &PreKeyRecord);

  fn contains_pre_key(&self, pre_key_id: u32) -> bool;

  fn remove_pre_key(&mut self, pre_key_id: u32);
}

pub trait SignedPreKeyStore {
  fn load_signed_pre_key(
    &self,
    signed_pre_key_id: u32,
  ) -> Option<&SignedPreKeyRecord>;

  fn load_signed_pre_keys(&self) -> Vec<&SignedPreKeyRecord>;

  fn store_signed_pre_key(
    &mut self,
    signed_pre_key_id: u32,
    record: &SignedPreKeyRecord,
  );

  fn contains_signed_pre_key(&self, signed_pre_key_id: u32) -> bool;

  fn remove_signed_pre_key(&mut self, signed_pre_key_id: u32);
}

pub trait SignalProtocolStore:
  IdentityKeyStore + SignedPreKeyStore + PreKeyStore
{
}
