use failure::Fail;
#[derive(Copy, Clone, Debug, Fail, PartialEq, Eq)]
pub enum SignalError {
  #[fail(display = "invalid key: {}", _0)]
  InvalidKey(&'static str),

  #[fail(display = "invalid signature: {}", _0)]
  InvalidSignature(&'static str),

  #[fail(display = "Error while generating signature")]
  SignatureFailure,
}
