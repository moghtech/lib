use std::fmt;

use serde::{Deserialize, Serialize};
use typeshare::typeshare;

use crate::cbor::{self, Value};

/// The format version this crate reads: the `v` of a payload.
pub const FORMAT_VERSION: u64 = 1;

/// The most bytes a payload may have.
pub const MAX_PAYLOAD_BYTES: usize = 4096;

/// The `t` of a payload. Serialized as its text, `individual`,
/// `organization` or `sponsor`.
#[typeshare]
#[derive(
  Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash,
)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
  Individual,
  Organization,
  Sponsor,
}

impl Tier {
  /// The text of the payload: `individual`, `organization` or
  /// `sponsor`.
  pub fn as_str(&self) -> &'static str {
    match self {
      Tier::Individual => "individual",
      Tier::Organization => "organization",
      Tier::Sponsor => "sponsor",
    }
  }
}

impl fmt::Display for Tier {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(self.as_str())
  }
}

impl std::str::FromStr for Tier {
  type Err = PayloadError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "individual" => Ok(Tier::Individual),
      "organization" => Ok(Tier::Organization),
      "sponsor" => Ok(Tier::Sponsor),
      _ => Err(PayloadError::Tier),
    }
  }
}

/// The payload of a supporter key (`P`), decoded. Decoding trusts
/// nothing: the payload is what it says once the root signature
/// over it verifies ([crate::SupporterKey::verify]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
  /// `v`. Only [FORMAT_VERSION] is valid.
  pub version: u64,
  /// `k`: the id of the root key which signed the key, see
  /// [crate::root_key_id] ([Self::root_key_id_hex]).
  pub root_key_id: [u8; 8],
  /// `i`: the id of the key, a UUID ([Self::id_string]). The
  /// revocation list names these.
  pub id: [u8; 16],
  /// `a`: the app the key is for, `komodo` or `cicada`.
  pub app: String,
  /// `n`: the name the badge shows.
  pub name: String,
  /// `t`.
  pub tier: Tier,
  /// `s`: supporter since, `YYYY-MM-DD`. Shown, not checked.
  pub since: String,
  /// `c`: the last release date the key covers, `YYYY-MM-DD`. A
  /// release published up to this date shows the badge, forever.
  pub covers: String,
}

/// Why bytes are not a payload. Never echoes them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
  #[error(
    "The payload is {0} bytes, the most is {MAX_PAYLOAD_BYTES}"
  )]
  TooLong(usize),
  #[error("The payload is not valid CBOR | {0}")]
  Cbor(#[from] cbor::Error),
  #[error("The payload is not a map")]
  NotAMap,
  #[error("The payload has no `{0}`")]
  Missing(&'static str),
  #[error("The `{0}` of the payload is not {1}")]
  Type(&'static str, &'static str),
  #[error(
    "The `{field}` of the payload is {got} bytes, expected {expected}"
  )]
  Length {
    field: &'static str,
    expected: usize,
    got: usize,
  },
  #[error("The `{0}` of the payload is not a `YYYY-MM-DD` date")]
  Date(&'static str),
  #[error(
    "The `t` of the payload is not `individual`, `organization` or `sponsor`"
  )]
  Tier,
}

impl Payload {
  /// Decodes the payload bytes of a key. Fields this version does
  /// not know are ignored.
  pub fn decode(bytes: &[u8]) -> Result<Payload, PayloadError> {
    if bytes.len() > MAX_PAYLOAD_BYTES {
      return Err(PayloadError::TooLong(bytes.len()));
    }
    let value = cbor::decode(bytes)?;
    Self::from_cbor(&value)
  }

  /// The payload of a decoded CBOR map.
  pub fn from_cbor(value: &Value) -> Result<Payload, PayloadError> {
    if !matches!(value, Value::Map(_)) {
      return Err(PayloadError::NotAMap);
    }
    Ok(Payload {
      version: unsigned(value, "v")?,
      root_key_id: bytes(value, "k")?,
      id: bytes(value, "i")?,
      app: text(value, "a")?.to_string(),
      name: text(value, "n")?.to_string(),
      tier: text(value, "t")?.parse()?,
      since: date(value, "s")?,
      covers: date(value, "c")?,
    })
  }

  /// The id (`i`) as a lowercase hyphenated UUID (8-4-4-4-12), the
  /// form the revocation list uses.
  pub fn id_string(&self) -> String {
    let hex = hex(&self.id);
    format!(
      "{}-{}-{}-{}-{}",
      &hex[0..8],
      &hex[8..12],
      &hex[12..16],
      &hex[16..20],
      &hex[20..32]
    )
  }

  /// The root key id (`k`) as lowercase hex, the form
  /// [crate::root_key_id] derives from a root key.
  pub fn root_key_id_hex(&self) -> String {
    hex(&self.root_key_id)
  }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
  use fmt::Write as _;
  let mut hex = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    // Writing to a String can't fail.
    let _ = write!(hex, "{byte:02x}");
  }
  hex
}

fn field<'a>(
  map: &'a Value,
  name: &'static str,
) -> Result<&'a Value, PayloadError> {
  map.get(name).ok_or(PayloadError::Missing(name))
}

fn unsigned(
  map: &Value,
  name: &'static str,
) -> Result<u64, PayloadError> {
  match field(map, name)? {
    Value::Unsigned(n) => Ok(*n),
    _ => Err(PayloadError::Type(name, "an unsigned integer")),
  }
}

fn bytes<const N: usize>(
  map: &Value,
  name: &'static str,
) -> Result<[u8; N], PayloadError> {
  match field(map, name)? {
    Value::Bytes(bytes) => {
      bytes
        .as_slice()
        .try_into()
        .map_err(|_| PayloadError::Length {
          field: name,
          expected: N,
          got: bytes.len(),
        })
    }
    _ => Err(PayloadError::Type(name, "a byte string")),
  }
}

fn text<'a>(
  map: &'a Value,
  name: &'static str,
) -> Result<&'a str, PayloadError> {
  match field(map, name)? {
    Value::Text(text) => Ok(text),
    _ => Err(PayloadError::Type(name, "text")),
  }
}

fn date(
  map: &Value,
  name: &'static str,
) -> Result<String, PayloadError> {
  let text = text(map, name)?;
  if is_date(text) {
    Ok(text.to_string())
  } else {
    Err(PayloadError::Date(name))
  }
}

/// Whether `text` has the form `YYYY-MM-DD`: digits and hyphens in
/// their places. Two such dates compare as strings.
pub fn is_date(text: &str) -> bool {
  let bytes = text.as_bytes();
  bytes.len() == 10
    && bytes.iter().enumerate().all(|(i, byte)| match i {
      4 | 7 => *byte == b'-',
      _ => byte.is_ascii_digit(),
    })
}
