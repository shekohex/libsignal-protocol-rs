use failure::Fail;
#[derive(Clone, Debug, Fail, PartialEq, Eq)]
pub enum SignalError {
  #[fail(display = "invalid key: {}", _0)]
  InvalidKey(String),

  #[fail(display = "invalid signature: {}", _0)]
  InvalidSignature(String),

  #[fail(display = "Error while generating signature")]
  SignatureFailure,

  #[fail(display = "Protocol Buffer Error: {}", _0)]
  ProtoBufError(String),
}
