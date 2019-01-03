use std::time::{SystemTime, UNIX_EPOCH};

/// A trait for converting a value to hexadecimal encoding
pub trait ToHex {
  /// Converts the value of `self` to a hex value, returning the owned
  /// string.
  fn to_hex(&self) -> String;
}

const CHARS: &[u8] = b"0123456789abcdef";

// From https://github.com/rust-lang/rust/blob/master/src/libserialize/hex.rs
impl ToHex for Vec<u8> {
  fn to_hex(&self) -> String {
    let mut v = Vec::with_capacity(self.len() * 2);
    for &byte in self {
      v.push(CHARS[(byte >> 4) as usize]);
      v.push(CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
  }
}

impl ToHex for &[u8] {
  fn to_hex(&self) -> String {
    let mut v = Vec::with_capacity(self.len() * 2);
    for &byte in self.iter() {
      v.push(CHARS[(byte >> 4) as usize]);
      v.push(CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
  }
}

impl ToHex for [u8] {
  fn to_hex(&self) -> String {
    let mut v = Vec::with_capacity(self.len() * 2);
    for &byte in self.iter() {
      v.push(CHARS[(byte >> 4) as usize]);
      v.push(CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
  }
}

impl ToHex for &str {
  fn to_hex(&self) -> String {
    let mut v = Vec::with_capacity(self.len() * 2);
    for byte in self.chars() {
      v.push(CHARS[(byte as u8 >> 4) as usize]);
      v.push(CHARS[(byte as u8 & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
  }
}

#[inline]
pub(crate) fn byte_array5_to_u64(bytes: &[u8], offset: usize) -> u64 {
  (bytes[offset].wrapping_shl(32)
    | bytes[offset + 1].wrapping_shl(24)
    | bytes[offset + 2].wrapping_shl(16)
    | bytes[offset + 3].wrapping_shl(8)
    | bytes[offset + 4])
    .into()
}

/// Compare `S1` and `S2`, returning less than, equal to or
/// greater than zero if `S1` is lexicographically less than,
/// equal to or greater than `S2`.
#[inline]
pub(crate) fn strcmp(s1: &str, s2: &str) -> isize {
  use std::cmp;
  let mlen = cmp::min(s1.len(), s2.len());
  let b1 = s1.as_bytes();
  let b2 = s2.as_bytes();
  for i in 0..mlen {
    let c1 = b1[i] as i8;
    let c2 = b2[i] as i8;
    if c1 != c2 {
      return (c1.wrapping_sub(c2)) as isize;
    }
  }
  (s1.len().wrapping_sub(s2.len())) as isize
}

pub(crate) fn current_timestamp_ms() -> u64 {
  let start = SystemTime::now();
  let since_the_epoch = start
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards");
  since_the_epoch.as_secs() * 1000 + u64::from(since_the_epoch.subsec_millis())
}

#[cfg(test)]
mod test_to_hex {
  use super::*;

  #[test]
  fn test_to_hex() {
    assert_eq!("foobar".to_hex(), "666f6f626172");
    assert_eq!(b"foobar".to_hex(), "666f6f626172");
    assert_eq!(String::from("foobar").as_bytes().to_hex(), "666f6f626172");
    assert_eq!(b"foobar".to_vec().to_hex(), "666f6f626172");
  }

  #[test]
  fn test_strcmp() {
    assert! {
      strcmp("test", "test") == 0
    }
    assert! {
      strcmp("testing", "test") > 0
    }
    assert! {
      strcmp("test", "testing") < 0
    }
    assert! {
      // Test non ascii
      strcmp("test ♥", "testing") < 0
    }
  }
}
