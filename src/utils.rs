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

pub(crate) fn byte_array5_to_u64(bytes: &[u8], offset: usize) -> u64 {
  (bytes[offset].wrapping_shl(32)
    | bytes[offset + 1].wrapping_shl(24)
    | bytes[offset + 2].wrapping_shl(16)
    | bytes[offset + 3].wrapping_shl(8)
    | bytes[offset + 4])
    .into()
}

#[cfg(test)]
mod test_to_hex {
  use super::ToHex;

  #[test]
  pub fn test_to_hex() {
    assert_eq!("foobar".to_hex(), "666f6f626172");
    assert_eq!(b"foobar".to_hex(), "666f6f626172");
    assert_eq!(String::from("foobar").as_bytes().to_hex(), "666f6f626172");
    assert_eq!(b"foobar".to_vec().to_hex(), "666f6f626172");
  }
}
