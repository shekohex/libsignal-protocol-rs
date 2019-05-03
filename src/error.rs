use failure::Fail;

#[derive(Clone, Debug, Fail, PartialEq, Eq)]
pub enum SignalError {
  #[fail(display = "invalid key: {}", _0)]
  InvalidKey(String),

  #[fail(display = "invalid signature: {}", _0)]
  InvalidSignature(String),

  #[fail(display = "invalid SessionVersion: {}", _0)]
  InvalidSessionVersion(String),

  #[fail(display = "Error while generating signature")]
  SignatureFailure,

  #[fail(display = "Protocol Buffer Error: {}", _0)]
  ProtoBufError(String),

  #[fail(
    display = "The Given Buffer was too small expected: {} bytes at least",
    _0
  )]
  BufferTooSmall(usize),

  #[fail(display = "Missing: {}", _0)]
  NoneError(String),
}
