//! The subset of CBOR (RFC 8949) a supporter key payload is encoded
//! in: unsigned and negative integers, byte and text strings, arrays
//! and maps of definite length, `false`, `true` and `null`. Arrays
//! and maps are decoded whole, which is what lets a field this
//! version does not know be skipped. Everything else is refused:
//! indefinite lengths, tags, floats, other simple values, duplicate
//! map keys and bytes after the item.

/// The most nested arrays / maps [decode] follows.
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
  /// Major type 0.
  Unsigned(u64),
  /// Major type 1: the value is `-1 - n`.
  Negative(u64),
  Bytes(Vec<u8>),
  Text(String),
  Array(Vec<Value>),
  /// The pairs in the order encoded. Keys are unique.
  Map(Vec<(Value, Value)>),
  Bool(bool),
  Null,
}

impl Value {
  /// The value under a text key, for a map. `None` for any other
  /// value.
  pub fn get(&self, key: &str) -> Option<&Value> {
    match self {
      Value::Map(pairs) => pairs.iter().find_map(|(k, v)| match k {
        Value::Text(k) if k == key => Some(v),
        _ => None,
      }),
      _ => None,
    }
  }
}

/// Why bytes are not an item of the subset. Positions are byte
/// offsets into the input, the input itself is never echoed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
  #[error("Unexpected end of input at byte {0}")]
  UnexpectedEnd(usize),
  #[error("Indefinite length item at byte {0}")]
  Indefinite(usize),
  #[error("Tag at byte {0}")]
  Tag(usize),
  #[error("Float at byte {0}")]
  Float(usize),
  #[error(
    "Unsupported item (major type {major}, additional information {info}) at byte {at}"
  )]
  Unsupported { major: u8, info: u8, at: usize },
  #[error("Text is not utf8 at byte {0}")]
  Utf8(usize),
  #[error("Duplicate map key at byte {0}")]
  DuplicateKey(usize),
  #[error("Nested deeper than {MAX_DEPTH} at byte {0}")]
  TooDeep(usize),
  #[error("{0} bytes follow the item")]
  TrailingBytes(usize),
}

/// Decodes `bytes` as exactly one item of the subset.
pub fn decode(bytes: &[u8]) -> Result<Value, Error> {
  let mut decoder = Decoder { bytes, at: 0 };
  let value = decoder.item(0)?;
  if decoder.at < bytes.len() {
    return Err(Error::TrailingBytes(bytes.len() - decoder.at));
  }
  Ok(value)
}

struct Decoder<'a> {
  bytes: &'a [u8],
  at: usize,
}

impl Decoder<'_> {
  fn byte(&mut self) -> Result<u8, Error> {
    let byte = *self
      .bytes
      .get(self.at)
      .ok_or(Error::UnexpectedEnd(self.at))?;
    self.at += 1;
    Ok(byte)
  }

  fn take(&mut self, len: u64) -> Result<&[u8], Error> {
    let end = usize::try_from(len)
      .ok()
      .and_then(|len| self.at.checked_add(len))
      .ok_or(Error::UnexpectedEnd(self.at))?;
    let slice = self
      .bytes
      .get(self.at..end)
      .ok_or(Error::UnexpectedEnd(self.at))?;
    self.at = end;
    Ok(slice)
  }

  /// The argument of an item: inline for additional information 0
  /// to 23, else the next 1, 2, 4 or 8 bytes, big endian.
  fn argument(
    &mut self,
    major: u8,
    info: u8,
    at: usize,
  ) -> Result<u64, Error> {
    match info {
      0..=23 => Ok(info as u64),
      24 => Ok(self.byte()? as u64),
      25 => {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64)
      }
      26 => {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([
          bytes[0], bytes[1], bytes[2], bytes[3],
        ]) as u64)
      }
      27 => {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
          bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
          bytes[6], bytes[7],
        ]))
      }
      31 => Err(Error::Indefinite(at)),
      _ => Err(Error::Unsupported { major, info, at }),
    }
  }

  /// The item count of an array / map. Every item takes at least one
  /// byte of input, so a count past the input is refused before
  /// anything is read or allocated for it.
  fn count(
    &mut self,
    major: u8,
    info: u8,
    at: usize,
  ) -> Result<u64, Error> {
    let count = self.argument(major, info, at)?;
    if count > (self.bytes.len() - self.at) as u64 {
      return Err(Error::UnexpectedEnd(self.at));
    }
    Ok(count)
  }

  fn item(&mut self, depth: usize) -> Result<Value, Error> {
    let at = self.at;
    let initial = self.byte()?;
    let major = initial >> 5;
    let info = initial & 0x1f;
    match major {
      0 => Ok(Value::Unsigned(self.argument(major, info, at)?)),
      1 => Ok(Value::Negative(self.argument(major, info, at)?)),
      2 => {
        let len = self.argument(major, info, at)?;
        Ok(Value::Bytes(self.take(len)?.to_vec()))
      }
      3 => {
        let len = self.argument(major, info, at)?;
        let text = std::str::from_utf8(self.take(len)?)
          .map_err(|_| Error::Utf8(at))?;
        Ok(Value::Text(text.to_string()))
      }
      4 => {
        if depth >= MAX_DEPTH {
          return Err(Error::TooDeep(at));
        }
        let len = self.count(major, info, at)?;
        let mut items = Vec::new();
        for _ in 0..len {
          items.push(self.item(depth + 1)?);
        }
        Ok(Value::Array(items))
      }
      5 => {
        if depth >= MAX_DEPTH {
          return Err(Error::TooDeep(at));
        }
        let len = self.count(major, info, at)?;
        let mut pairs: Vec<(Value, Value)> = Vec::new();
        for _ in 0..len {
          let key_at = self.at;
          let key = self.item(depth + 1)?;
          if pairs.iter().any(|(k, _)| *k == key) {
            return Err(Error::DuplicateKey(key_at));
          }
          let value = self.item(depth + 1)?;
          pairs.push((key, value));
        }
        Ok(Value::Map(pairs))
      }
      6 => Err(Error::Tag(at)),
      _ => match info {
        20 => Ok(Value::Bool(false)),
        21 => Ok(Value::Bool(true)),
        22 => Ok(Value::Null),
        25..=27 => Err(Error::Float(at)),
        31 => Err(Error::Indefinite(at)),
        _ => Err(Error::Unsupported { major, info, at }),
      },
    }
  }
}
