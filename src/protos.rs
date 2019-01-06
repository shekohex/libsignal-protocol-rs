use prost_derive::Message;

pub(crate) mod textsecure {
  use super::*;

  #[derive(Clone, PartialEq, Message)]
  pub struct LogicalFingerprint {
    ///  optional bytes identifier = 2;
    #[prost(bytes, optional, tag = "1")]
    pub content: Option<Vec<u8>>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct CombinedFingerprints {
    #[prost(uint32, optional, tag = "1")]
    pub version: Option<u32>,
    #[prost(message, optional, tag = "2")]
    pub local_fingerprint: Option<LogicalFingerprint>,
    #[prost(message, optional, tag = "3")]
    pub remote_fingerprint: Option<LogicalFingerprint>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct SessionStructure {
    #[prost(uint32, optional, tag = "1")]
    pub session_version: Option<u32>,
    #[prost(bytes, optional, tag = "2")]
    pub local_identity_public: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub remote_identity_public: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "4")]
    pub root_key: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "5")]
    pub previous_counter: Option<u32>,
    #[prost(message, optional, tag = "6")]
    pub sender_chain: Option<session_structure::Chain>,
    #[prost(message, repeated, tag = "7")]
    pub receiver_chains: Vec<session_structure::Chain>,
    #[prost(message, optional, tag = "8")]
    pub pending_key_exchange: Option<session_structure::PendingKeyExchange>,
    #[prost(message, optional, tag = "9")]
    pub pending_pre_key: Option<session_structure::PendingPreKey>,
    #[prost(uint32, optional, tag = "10")]
    pub remote_registration_id: Option<u32>,
    #[prost(uint32, optional, tag = "11")]
    pub local_registration_id: Option<u32>,
    #[prost(bool, optional, tag = "12")]
    pub needs_refresh: Option<bool>,
    #[prost(bytes, optional, tag = "13")]
    pub alice_base_key: Option<Vec<u8>>,
  }
  pub mod session_structure {
    use super::*;

    #[derive(Clone, PartialEq, Message)]
    pub struct Chain {
      #[prost(bytes, optional, tag = "1")]
      pub sender_ratchet_key: Option<Vec<u8>>,
      #[prost(bytes, optional, tag = "2")]
      pub sender_ratchet_key_private: Option<Vec<u8>>,
      #[prost(message, optional, tag = "3")]
      pub chain_key: Option<chain::ChainKey>,
      #[prost(message, repeated, tag = "4")]
      pub message_keys: Vec<chain::MessageKey>,
    }
    pub mod chain {
      use super::*;

      #[derive(Clone, PartialEq, Message)]
      pub struct ChainKey {
        #[prost(uint32, optional, tag = "1")]
        pub index: Option<u32>,
        #[prost(bytes, optional, tag = "2")]
        pub key: Option<Vec<u8>>,
      }
      #[derive(Clone, PartialEq, Message)]
      pub struct MessageKey {
        #[prost(uint32, optional, tag = "1")]
        pub index: Option<u32>,
        #[prost(bytes, optional, tag = "2")]
        pub cipher_key: Option<Vec<u8>>,
        #[prost(bytes, optional, tag = "3")]
        pub mac_key: Option<Vec<u8>>,
        #[prost(bytes, optional, tag = "4")]
        pub iv: Option<Vec<u8>>,
      }
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct PendingKeyExchange {
      #[prost(uint32, optional, tag = "1")]
      pub sequence: Option<u32>,
      #[prost(bytes, optional, tag = "2")]
      pub local_base_key: Option<Vec<u8>>,
      #[prost(bytes, optional, tag = "3")]
      pub local_base_key_private: Option<Vec<u8>>,
      #[prost(bytes, optional, tag = "4")]
      pub local_ratchet_key: Option<Vec<u8>>,
      #[prost(bytes, optional, tag = "5")]
      pub local_ratchet_key_private: Option<Vec<u8>>,
      #[prost(bytes, optional, tag = "7")]
      pub local_identity_key: Option<Vec<u8>>,
      #[prost(bytes, optional, tag = "8")]
      pub local_identity_key_private: Option<Vec<u8>>,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct PendingPreKey {
      #[prost(uint32, optional, tag = "1")]
      pub pre_key_id: Option<u32>,
      #[prost(int32, optional, tag = "3")]
      pub signed_pre_key_id: Option<i32>,
      #[prost(bytes, optional, tag = "2")]
      pub base_key: Option<Vec<u8>>,
    }
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct RecordStructure {
    #[prost(message, optional, tag = "1")]
    pub current_session: Option<SessionStructure>,
    #[prost(message, repeated, tag = "2")]
    pub previous_sessions: Vec<SessionStructure>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct PreKeyRecordStructure {
    #[prost(uint32, optional, tag = "1")]
    pub id: Option<u32>,
    #[prost(bytes, optional, tag = "2")]
    pub public_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub private_key: Option<Vec<u8>>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct SignedPreKeyRecordStructure {
    #[prost(uint32, optional, tag = "1")]
    pub id: Option<u32>,
    #[prost(bytes, optional, tag = "2")]
    pub public_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub private_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "4")]
    pub signature: Option<Vec<u8>>,
    #[prost(fixed64, optional, tag = "5")]
    pub timestamp: Option<u64>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct IdentityKeyPairStructure {
    #[prost(bytes, optional, tag = "1")]
    pub public_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "2")]
    pub private_key: Option<Vec<u8>>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct SenderKeyStateStructure {
    #[prost(uint32, optional, tag = "1")]
    pub sender_key_id: Option<u32>,
    #[prost(message, optional, tag = "2")]
    pub sender_chain_key: Option<sender_key_state_structure::SenderChainKey>,
    #[prost(message, optional, tag = "3")]
    pub sender_signing_key:
      Option<sender_key_state_structure::SenderSigningKey>,
    #[prost(message, repeated, tag = "4")]
    pub sender_message_keys: Vec<sender_key_state_structure::SenderMessageKey>,
  }
  pub mod sender_key_state_structure {
    use super::*;

    #[derive(Clone, PartialEq, Message)]
    pub struct SenderChainKey {
      #[prost(uint32, optional, tag = "1")]
      pub iteration: Option<u32>,
      #[prost(bytes, optional, tag = "2")]
      pub seed: Option<Vec<u8>>,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct SenderMessageKey {
      #[prost(uint32, optional, tag = "1")]
      pub iteration: Option<u32>,
      #[prost(bytes, optional, tag = "2")]
      pub seed: Option<Vec<u8>>,
    }
    #[derive(Clone, PartialEq, Message)]
    pub struct SenderSigningKey {
      #[prost(bytes, optional, tag = "1")]
      pub public: Option<Vec<u8>>,
      #[prost(bytes, optional, tag = "2")]
      pub private: Option<Vec<u8>>,
    }
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct SenderKeyRecordStructure {
    #[prost(message, repeated, tag = "1")]
    pub sender_key_states: Vec<SenderKeyStateStructure>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct SignalMessage {
    #[prost(bytes, optional, tag = "1")]
    pub ratchet_key: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "2")]
    pub counter: Option<u32>,
    #[prost(uint32, optional, tag = "3")]
    pub previous_counter: Option<u32>,
    #[prost(bytes, optional, tag = "4")]
    pub ciphertext: Option<Vec<u8>>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct PreKeySignalMessage {
    #[prost(uint32, optional, tag = "5")]
    pub registration_id: Option<u32>,
    #[prost(uint32, optional, tag = "1")]
    pub pre_key_id: Option<u32>,
    #[prost(uint32, optional, tag = "6")]
    pub signed_pre_key_id: Option<u32>,
    #[prost(bytes, optional, tag = "2")]
    pub base_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub identity_key: Option<Vec<u8>>,
    /// SignalMessage
    #[prost(bytes, optional, tag = "4")]
    pub message: Option<Vec<u8>>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct KeyExchangeMessage {
    #[prost(uint32, optional, tag = "1")]
    pub id: Option<u32>,
    #[prost(bytes, optional, tag = "2")]
    pub base_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "3")]
    pub ratchet_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "4")]
    pub identity_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "5")]
    pub base_key_signature: Option<Vec<u8>>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct SenderKeyMessage {
    #[prost(uint32, optional, tag = "1")]
    pub id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub iteration: Option<u32>,
    #[prost(bytes, optional, tag = "3")]
    pub ciphertext: Option<Vec<u8>>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct SenderKeyDistributionMessage {
    #[prost(uint32, optional, tag = "1")]
    pub id: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub iteration: Option<u32>,
    #[prost(bytes, optional, tag = "3")]
    pub chain_key: Option<Vec<u8>>,
    #[prost(bytes, optional, tag = "4")]
    pub signing_key: Option<Vec<u8>>,
  }
  #[derive(Clone, PartialEq, Message)]
  pub struct DeviceConsistencyCodeMessage {
    #[prost(uint32, optional, tag = "1")]
    pub generation: Option<u32>,
    #[prost(bytes, optional, tag = "2")]
    pub signature: Option<Vec<u8>>,
  }

}
