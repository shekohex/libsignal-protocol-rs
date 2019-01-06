use either::Either;
use getset::Getters;
use prost::Message;

use crate::{
    ecc::{Curve, DjbECKey, ECKey, ECKeyPair},
    error::SignalError,
    identity_key::{IdentityKey, IdentityKeyPair},
    kdf::{HKDF, HKDFv2, HKDFv3},
    protos::textsecure::{
        PreKeyRecordStructure,
        session_structure::{chain, Chain}, SessionStructure, SignedPreKeyRecordStructure,
  },
    ratchet::{ChainKey, RootKey},
    signal::SignalProtocolAddress,
};

// const ARCHIVED_STATES_MAX_LENGTH: u8 = 40;
// const MAX_MESSAGE_KEYS: u8 = 2000;

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

#[derive(Clone, Debug, Default, Getters)]
pub struct SessionState {
  #[get = "pub"]
  structure: SessionStructure,
}

impl SessionState {
  pub fn new() -> Self { Self::default() }

  pub fn with_structure(structure: SessionStructure) -> Self {
    Self { structure }
  }

  pub fn from_copy(copy: &Self) -> Self {
    Self {
      structure: copy.structure.clone(),
    }
  }

  pub fn get_alice_base_key(&self) -> &Option<Vec<u8>> {
    &self.structure.alice_base_key
  }

  pub fn set_alice_base_key(&mut self, key: Vec<u8>) {
    self.structure.alice_base_key = Some(key);
  }

  pub fn get_session_version(&self) -> u32 {
    if let Some(ver) = self.structure.session_version {
      if ver == 0 {
        2
      } else {
        ver
      }
    } else {
      2
    }
  }

  pub fn set_session_version(&mut self, ver: u32) {
    self.structure.session_version = Some(ver);
  }

  pub fn set_local_identity_key<K: ECKey>(&mut self, key: &IdentityKey<K>) {
    self.structure.local_identity_public = Some(key.serialize());
  }

  pub fn set_remote_identity_key<K: ECKey>(&mut self, key: &IdentityKey<K>) {
    self.structure.remote_identity_public = Some(key.serialize());
  }

  pub fn get_remote_identity_key<K: ECKey>(&self) -> Option<IdentityKey<K>> {
    if let Some(key) = &self.structure.remote_identity_public {
      IdentityKey::from_raw(&key, 0).ok()
    } else {
      None
    }
  }

  pub fn get_local_identity_key<K: ECKey>(
    &self,
  ) -> Result<IdentityKey<K>, SignalError> {
    if let Some(key) = &self.structure.local_identity_public {
      IdentityKey::from_raw(&key, 0)
    } else {
      Err(SignalError::InvalidKey("Missing LocalKey".to_string()))
    }
  }

  pub fn get_previous_counter(&self) -> &Option<u32> {
    &self.structure.previous_counter
  }

  pub fn set_previous_counter(&mut self, previous_counter: u32) {
    self.structure.previous_counter = Some(previous_counter);
  }

  pub fn get_root_key(
    &self,
  ) -> Result<Either<RootKey<HKDFv2>, RootKey<HKDFv3>>, SignalError> {
    if let Some(key) = &self.structure.root_key {
      let ver = self.get_session_version();
      if ver == 2 {
        Ok(Either::Left(RootKey::new(HKDFv2, key)))
      } else if ver == 3 {
        Ok(Either::Right(RootKey::new(HKDFv3, key)))
      } else {
        Err(SignalError::InvalidSessionVersion(
          "Unknown Version (not 2 or 3)".to_string(),
        ))
      }
    } else {
      Err(SignalError::InvalidSessionVersion(
        "Missing Version".to_string(),
      ))
    }
  }

  pub fn set_root_key<K: HKDF + Clone>(&mut self, key: &RootKey<K>) {
    self.structure.remote_identity_public = Some(key.key().to_vec());
  }

  pub fn get_sender_ratchet_key<K: ECKey>(&self) -> Result<K, SignalError> {
    if let Some(sender_chain) = &self.structure.sender_chain {
      if let Some(key) = &sender_chain.sender_ratchet_key {
        Curve::decode_point(&key, 0)
      } else {
        Err(SignalError::InvalidKey(
          "Missing Sender Retchet Key".to_string(),
        ))
      }
    } else {
      Err(SignalError::InvalidKey("Missing Sender Chain".to_string()))
    }
  }

  pub fn get_sender_ratchet_key_pair<K: ECKey>(
    &self,
  ) -> Result<ECKeyPair<K>, SignalError> {
    let public_key = self.get_sender_ratchet_key::<K>()?;
    if let Some(sender_chain) = &self.structure.sender_chain {
      if let Some(key) = &sender_chain.sender_ratchet_key_private {
        let private_key = Curve::decode_private_point(&key);
        Ok(ECKeyPair::new(public_key, private_key))
      } else {
        Err(SignalError::InvalidKey(
          "Missing Sender Retchet Private Key".to_string(),
        ))
      }
    } else {
      Err(SignalError::InvalidKey("Missing Sender Chain".to_string()))
    }
  }

  pub fn get_receiver_chain<K: ECKey>(
    &self,
    sender_ephemeral: &K,
  ) -> Option<(Chain, usize)> {
    let receiver_chains = self.structure.receiver_chains.clone();
    for (i, receiver_chain) in receiver_chains.into_iter().enumerate() {
      let chain_sender_ratchet_key =
        receiver_chain.clone().sender_ratchet_key?;
      let pub_key: K =
        Curve::decode_point(&chain_sender_ratchet_key, 0).ok()?;
      if pub_key == *sender_ephemeral {
        return Some((receiver_chain, i));
      }
    }
    None
  }

  pub fn has_receiver_chain<K: ECKey>(&self, sender_ephemeral: &K) -> bool {
    self.get_receiver_chain(sender_ephemeral).is_some()
  }

  pub fn has_sender_chain(&self) -> bool {
    self.structure.sender_chain.is_some()
  }

  pub fn get_receiver_chain_key<K: ECKey>(
    &self,
    sender_ephemeral: &K,
  ) -> Option<Either<ChainKey<HKDFv2>, ChainKey<HKDFv3>>> {
    let receiver_chain_index = self.get_receiver_chain(sender_ephemeral);
    if let Some((chain, _index)) = receiver_chain_index {
      let ver = self.get_session_version();
      if ver == 2 {
        Some(Either::Left(ChainKey::new(
          HKDFv2,
          &chain.clone().chain_key?.key?,
          chain.chain_key?.index?,
        )))
      } else if ver == 3 {
        Some(Either::Right(ChainKey::new(
          HKDFv3,
          &chain.clone().chain_key?.key?,
          chain.chain_key?.index?,
        )))
      } else {
        None
      }
    } else {
      None
    }
  }

  pub fn add_receiver_chain_key<K: ECKey, H: HKDF>(
    &mut self,
    sender_ratchet_key: &K,
    chain_key: &ChainKey<H>,
  ) {
    let mut chain_key_structure = chain::ChainKey::default();
    chain_key_structure.key = Some(chain_key.key().to_vec());
    chain_key_structure.index = Some(*chain_key.index());
    let mut chain_structure = Chain::default();
    chain_structure.chain_key = Some(chain_key_structure);
    chain_structure.sender_ratchet_key = Some(sender_ratchet_key.serialize());
    self.structure.receiver_chains.push(chain_structure);
    let chain_size = self.structure.receiver_chains.len();
    if chain_size > 5 {
      self.structure.receiver_chains.remove(0);
    }
  }

  pub fn set_sender_chain<K: ECKey, H: HKDF>(
    &mut self,
    sender_ratchet_key_pair: &ECKeyPair<K>,
    chain_key: &ChainKey<H>,
  ) {
    let mut chain_key_structure = chain::ChainKey::default();
    chain_key_structure.key = Some(chain_key.key().to_vec());
    chain_key_structure.index = Some(*chain_key.index());
    let mut sender_chain_structure: Chain = Chain::default();
    sender_chain_structure.chain_key = Some(chain_key_structure);
    sender_chain_structure.sender_ratchet_key =
      Some(sender_ratchet_key_pair.public_key().serialize().to_vec());
    sender_chain_structure.sender_ratchet_key_private =
      Some(sender_ratchet_key_pair.private_key().serialize().to_vec());
    self.structure.sender_chain = Some(sender_chain_structure);
  }

  // TODO: add more methods from `libsignal/state/SessionState.java`

  pub fn serialize(&self) -> Result<Vec<u8>, SignalError> {
    let mut result = Vec::new();
    self
      .structure
      .encode(&mut result)
      .map_err(|e| SignalError::ProtoBufError(e.to_string()))?;
    Ok(result)
  }
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
