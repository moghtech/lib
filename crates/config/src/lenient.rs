//! The final deserialization, lenient about strings the way `envy`
//! reads the process environment: a string value coerces into the
//! type the struct asks for. Configuration arrives as strings from
//! env file sources and from `${VAR}` interpolation, and a `port:
//! u16` field must accept `PORT=8080` all the same.
//!
//! - `bool`, integers and floats parse from the (trimmed) string; a
//!   `char` is the string's single character, untrimmed, so
//!   whitespace such as `" "` or a tab stays a valid char.
//! - A sequence (`Vec<T>`, tuples) splits a string on commas,
//!   entries trimmed and empty ones dropped, so `""` is an empty
//!   list; each entry coerces in turn. A tuple or `[T; N]` given
//!   more entries than it has is an error, as in serde_json.
//! - `Option<T>` is `Some` (only `null` is `None`).
//! - A unit enum variant matches the string.
//! - A `String` stays what it is.
//! - A map key (a string in json) coerces into the map's key type
//!   the same way, as serde_json reads keys: `{ "8080": "api" }`
//!   into a `HashMap<u16, String>`, a `bool`, a newtype around
//!   either, a unit enum variant.
//!
//! Every other value, and every nested map or array, deserializes
//! as `serde_json::Value` does, with the same leniency applied to
//! their children, including the payload of an externally tagged
//! enum variant (`{ "Vault": { "port": "8200" } }`).
//!
//! Out of reach: anything serde buffers before deserializing it,
//! that is `#[serde(flatten)]` fields, untagged enums and
//! internally / adjacently tagged enums. serde reads those through
//! `deserialize_any`, where a string is a string, so a numeric field
//! inside them must arrive typed (from toml / yaml / json), not from
//! an env file.

use serde::{
  Deserializer, de::IntoDeserializer as _, de::Visitor,
  forward_to_deserialize_any,
};
use serde_json::{Error, Value};

pub(crate) struct Lenient(pub(crate) Value);

impl Lenient {
  fn string(&self) -> Option<&str> {
    match &self.0 {
      Value::String(s) => Some(s),
      _ => None,
    }
  }
}

macro_rules! coerce_number {
  ($method:ident, $ty:ty, $visit:ident) => {
    fn $method<V>(self, visitor: V) -> Result<V::Value, Error>
    where
      V: Visitor<'de>,
    {
      match self.string() {
        Some(s) => {
          let n = s.trim().parse::<$ty>().map_err(|_| {
            serde::de::Error::invalid_value(
              serde::de::Unexpected::Str(s),
              &visitor,
            )
          })?;
          visitor.$visit(n)
        }
        None => self.0.$method(visitor),
      }
    }
  };
}

impl<'de> Deserializer<'de> for Lenient {
  type Error = Error;

  fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    match self.0 {
      Value::Null => visitor.visit_unit(),
      Value::Bool(b) => visitor.visit_bool(b),
      Value::Number(n) => n.deserialize_any(visitor),
      Value::String(s) => visitor.visit_string(s),
      Value::Array(items) => visit_array(items, visitor),
      Value::Object(map) => visit_object(map, visitor),
    }
  }

  fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    match self.string() {
      Some(s) => match s.trim().to_ascii_lowercase().as_str() {
        "true" => visitor.visit_bool(true),
        "false" => visitor.visit_bool(false),
        _ => Err(serde::de::Error::invalid_value(
          serde::de::Unexpected::Str(s),
          &visitor,
        )),
      },
      None => self.0.deserialize_bool(visitor),
    }
  }

  coerce_number!(deserialize_i8, i8, visit_i8);
  coerce_number!(deserialize_i16, i16, visit_i16);
  coerce_number!(deserialize_i32, i32, visit_i32);
  coerce_number!(deserialize_i64, i64, visit_i64);
  coerce_number!(deserialize_i128, i128, visit_i128);
  coerce_number!(deserialize_u8, u8, visit_u8);
  coerce_number!(deserialize_u16, u16, visit_u16);
  coerce_number!(deserialize_u32, u32, visit_u32);
  coerce_number!(deserialize_u64, u64, visit_u64);
  coerce_number!(deserialize_u128, u128, visit_u128);
  coerce_number!(deserialize_f32, f32, visit_f32);
  coerce_number!(deserialize_f64, f64, visit_f64);

  fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    match self.string() {
      Some(s) => {
        let mut chars = s.chars();
        match (chars.next(), chars.next()) {
          (Some(c), None) => visitor.visit_char(c),
          _ => Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Str(s),
            &visitor,
          )),
        }
      }
      None => self.0.deserialize_char(visitor),
    }
  }

  fn deserialize_option<V>(
    self,
    visitor: V,
  ) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    match self.0 {
      Value::Null => visitor.visit_none(),
      _ => visitor.visit_some(self),
    }
  }

  fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    match self.string() {
      Some(s) => visit_array(split_list(s), visitor),
      None => self.deserialize_any(visitor),
    }
  }

  fn deserialize_tuple<V>(
    self,
    _len: usize,
    visitor: V,
  ) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    self.deserialize_seq(visitor)
  }

  fn deserialize_tuple_struct<V>(
    self,
    _name: &'static str,
    _len: usize,
    visitor: V,
  ) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    self.deserialize_seq(visitor)
  }

  fn deserialize_enum<V>(
    self,
    name: &'static str,
    variants: &'static [&'static str],
    visitor: V,
  ) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    match self.0 {
      // A unit variant by name, as envy reads it.
      Value::String(s) => {
        visitor.visit_enum(serde::de::value::StringDeserializer::<
          Error,
        >::new(s))
      }
      // Externally tagged, `{ "Variant": payload }`: the payload
      // deserializes leniently too.
      Value::Object(map) if map.len() == 1 => {
        let (variant, payload) =
          map.into_iter().next().expect("one entry");
        visitor.visit_enum(ObjectEnum { variant, payload })
      }
      other => other.deserialize_enum(name, variants, visitor),
    }
  }

  fn deserialize_newtype_struct<V>(
    self,
    _name: &'static str,
    visitor: V,
  ) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    visitor.visit_newtype_struct(self)
  }

  fn deserialize_ignored_any<V>(
    self,
    visitor: V,
  ) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    visitor.visit_unit()
  }

  forward_to_deserialize_any! {
    str string bytes byte_buf unit unit_struct map struct identifier
  }
}

/// An externally tagged enum value, `{ "Variant": payload }`.
struct ObjectEnum {
  variant: String,
  payload: Value,
}

impl<'de> serde::de::EnumAccess<'de> for ObjectEnum {
  type Error = Error;
  type Variant = Lenient;

  fn variant_seed<V>(
    self,
    seed: V,
  ) -> Result<(V::Value, Self::Variant), Error>
  where
    V: serde::de::DeserializeSeed<'de>,
  {
    let variant =
      seed.deserialize(self.variant.into_deserializer())?;
    Ok((variant, Lenient(self.payload)))
  }
}

impl<'de> serde::de::VariantAccess<'de> for Lenient {
  type Error = Error;

  fn unit_variant(self) -> Result<(), Error> {
    match self.0 {
      Value::Null => Ok(()),
      other => Err(serde::de::Error::invalid_type(
        unexpected(&other),
        &"unit variant",
      )),
    }
  }

  fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Error>
  where
    T: serde::de::DeserializeSeed<'de>,
  {
    seed.deserialize(self)
  }

  fn tuple_variant<V>(
    self,
    _len: usize,
    visitor: V,
  ) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    self.deserialize_seq(visitor)
  }

  fn struct_variant<V>(
    self,
    _fields: &'static [&'static str],
    visitor: V,
  ) -> Result<V::Value, Error>
  where
    V: Visitor<'de>,
  {
    self.deserialize_any(visitor)
  }
}

/// The value's kind for a serde type error, never its contents.
fn unexpected(value: &Value) -> serde::de::Unexpected<'static> {
  use serde::de::Unexpected;
  match value {
    Value::Null => Unexpected::Unit,
    Value::Bool(b) => Unexpected::Bool(*b),
    Value::Number(_) => Unexpected::Other("number"),
    Value::String(_) => Unexpected::Other("string"),
    Value::Array(_) => Unexpected::Seq,
    Value::Object(_) => Unexpected::Map,
  }
}

/// A comma separated list, entries trimmed and empty ones dropped.
fn split_list(s: &str) -> Vec<Value> {
  s.split(',')
    .map(str::trim)
    .filter(|entry| !entry.is_empty())
    .map(|entry| Value::String(entry.to_string()))
    .collect()
}

/// Visits the items as a sequence. A visitor which stops early (a
/// tuple, `[T; N]`) leaving items unread is an error, as in
/// serde_json, rather than the rest being dropped silently.
fn visit_array<'de, V: Visitor<'de>>(
  items: Vec<Value>,
  visitor: V,
) -> Result<V::Value, Error> {
  let len = items.len();
  let mut seq = Seq {
    iter: items.into_iter(),
  };
  let value = visitor.visit_seq(&mut seq)?;
  if seq.iter.len() == 0 {
    Ok(value)
  } else {
    Err(serde::de::Error::invalid_length(
      len,
      &"fewer elements in array",
    ))
  }
}

/// Visits the entries as a map, erroring like [visit_array] on
/// entries left unread.
fn visit_object<'de, V: Visitor<'de>>(
  map: serde_json::Map<String, Value>,
  visitor: V,
) -> Result<V::Value, Error> {
  let len = map.len();
  let mut access = Map {
    iter: map.into_iter(),
    value: None,
  };
  let value = visitor.visit_map(&mut access)?;
  if access.iter.len() == 0 {
    Ok(value)
  } else {
    Err(serde::de::Error::invalid_length(
      len,
      &"fewer elements in map",
    ))
  }
}

struct Seq {
  iter: std::vec::IntoIter<Value>,
}

impl<'de> serde::de::SeqAccess<'de> for Seq {
  type Error = Error;

  fn next_element_seed<T>(
    &mut self,
    seed: T,
  ) -> Result<Option<T::Value>, Error>
  where
    T: serde::de::DeserializeSeed<'de>,
  {
    match self.iter.next() {
      Some(value) => seed.deserialize(Lenient(value)).map(Some),
      None => Ok(None),
    }
  }

  fn size_hint(&self) -> Option<usize> {
    Some(self.iter.len())
  }
}

struct Map {
  iter: serde_json::map::IntoIter,
  value: Option<Value>,
}

impl<'de> serde::de::MapAccess<'de> for Map {
  type Error = Error;

  fn next_key_seed<K>(
    &mut self,
    seed: K,
  ) -> Result<Option<K::Value>, Error>
  where
    K: serde::de::DeserializeSeed<'de>,
  {
    match self.iter.next() {
      Some((key, value)) => {
        self.value = Some(value);
        // A key coerces like a value (`"8080"` into a `u16`), as
        // serde_json reads keys.
        seed.deserialize(Lenient(Value::String(key))).map(Some)
      }
      None => Ok(None),
    }
  }

  fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Error>
  where
    V: serde::de::DeserializeSeed<'de>,
  {
    let value = self.value.take().unwrap_or(Value::Null);
    seed.deserialize(Lenient(value))
  }

  fn size_hint(&self) -> Option<usize> {
    Some(self.iter.len())
  }
}

#[cfg(test)]
mod tests {
  use serde::Deserialize;
  use serde_json::json;

  use super::*;

  fn from<T: for<'de> Deserialize<'de>>(
    value: Value,
  ) -> Result<T, Error> {
    T::deserialize(Lenient(value))
  }

  #[derive(Debug, Deserialize, PartialEq)]
  #[serde(rename_all = "lowercase")]
  enum Mode {
    Fast,
    Safe,
  }

  #[derive(Debug, Deserialize, PartialEq)]
  struct Config {
    port: u16,
    ratio: f64,
    debug: bool,
    name: String,
    hosts: Vec<String>,
    pins: Vec<u8>,
    mode: Mode,
    alias: Option<String>,
    missing: Option<u32>,
    initial: char,
    nested: Nested,
  }

  #[derive(Debug, Deserialize, PartialEq)]
  struct Nested {
    retries: i32,
    tags: Vec<String>,
  }

  #[test]
  fn strings_coerce_like_envy() {
    let config: Config = from(json!({
      "port": " 8080 ",
      "ratio": "0.5",
      "debug": "True",
      "name": "app",
      "hosts": "a.example.com, b.example.com,",
      "pins": "1, 2,3",
      "mode": "fast",
      "alias": "x",
      "missing": null,
      "initial": "c",
      "nested": { "retries": "3", "tags": "" },
    }))
    .unwrap();
    assert_eq!(
      config,
      Config {
        port: 8080,
        ratio: 0.5,
        debug: true,
        name: "app".into(),
        hosts: vec!["a.example.com".into(), "b.example.com".into()],
        pins: vec![1, 2, 3],
        mode: Mode::Fast,
        alias: Some("x".into()),
        missing: None,
        initial: 'c',
        nested: Nested {
          retries: 3,
          tags: Vec::new(),
        },
      }
    );
  }

  #[test]
  fn typed_values_still_deserialize_as_before() {
    let config: Config = from(json!({
      "port": 8080,
      "ratio": 0.5,
      "debug": true,
      "name": "app",
      "hosts": ["a", "b"],
      "pins": [1, 2],
      "mode": "safe",
      "alias": null,
      "missing": 7,
      "initial": "z",
      "nested": { "retries": -1, "tags": ["t"] },
    }))
    .unwrap();
    assert_eq!(config.port, 8080);
    assert_eq!(config.hosts, vec!["a", "b"]);
    assert_eq!(config.mode, Mode::Safe);
    assert_eq!(config.alias, None);
    assert_eq!(config.missing, Some(7));
    assert_eq!(config.nested.retries, -1);
    // A number into a string field is still a type error, as is a
    // string that does not parse.
    assert!(from::<String>(json!(1)).is_err());
    assert!(from::<u16>(json!("hunter2")).is_err());
    assert!(from::<bool>(json!("yes")).is_err());
    assert!(from::<char>(json!("ab")).is_err());
    // A char is not trimmed: whitespace is a char of its own.
    assert_eq!(from::<char>(json!(" ")).unwrap(), ' ');
    assert_eq!(from::<char>(json!("\t")).unwrap(), '\t');
    assert!(from::<char>(json!(" c")).is_err());
    assert!(from::<Mode>(json!("slow")).is_err());
  }

  #[test]
  fn externally_tagged_enum_payloads_coerce_too() {
    #[derive(Debug, Deserialize, PartialEq)]
    enum Provider {
      Vault { address: String, port: u16 },
      Local(u16),
      None,
    }
    let vault: Provider =
      from(json!({ "Vault": { "address": "v", "port": "8200" } }))
        .unwrap();
    assert_eq!(
      vault,
      Provider::Vault {
        address: "v".into(),
        port: 8200
      }
    );
    let local: Provider = from(json!({ "Local": "9" })).unwrap();
    assert_eq!(local, Provider::Local(9));
    let none: Provider = from(json!("None")).unwrap();
    assert_eq!(none, Provider::None);
    let none: Provider = from(json!({ "None": null })).unwrap();
    assert_eq!(none, Provider::None);
    assert!(from::<Provider>(json!({ "Nope": 1 })).is_err());
    assert!(from::<Provider>(json!({ "Local": "x" })).is_err());
  }

  /// Keys are strings in json; they coerce into the map's key type
  /// the way serde_json reads them (and 2.x did).
  #[test]
  fn map_keys_coerce_like_serde_json_keys() {
    use std::collections::{BTreeMap, HashMap};

    #[derive(Debug, Deserialize, PartialEq, Eq, Hash)]
    struct Id(String);

    #[derive(Debug, Deserialize, PartialEq, Eq, Hash)]
    struct Port(u16);

    let ports: HashMap<u16, String> =
      from(json!({ "8080": "api", "9090": "metrics" })).unwrap();
    assert_eq!(ports[&8080], "api");
    assert_eq!(ports[&9090], "metrics");

    let offsets: BTreeMap<i64, u32> =
      from(json!({ "-1": "1", "2": 2 })).unwrap();
    assert_eq!(offsets, BTreeMap::from([(-1, 1), (2, 2)]));

    let big: BTreeMap<u64, bool> =
      from(json!({ "18446744073709551615": "true" })).unwrap();
    assert_eq!(big, BTreeMap::from([(u64::MAX, true)]));

    let flags: HashMap<bool, String> =
      from(json!({ "true": "on", "false": "off" })).unwrap();
    assert_eq!(flags[&true], "on");
    assert_eq!(flags[&false], "off");

    let ids: HashMap<Id, u16> = from(json!({ "a": "1" })).unwrap();
    assert_eq!(ids[&Id("a".into())], 1);

    let ports: HashMap<Port, String> =
      from(json!({ "8080": "api" })).unwrap();
    assert_eq!(ports[&Port(8080)], "api");

    let modes: BTreeMap<String, Mode> =
      from(json!({ "x": "fast" })).unwrap();
    assert_eq!(modes["x"], Mode::Fast);

    #[derive(Debug, Deserialize, PartialEq, Eq, Hash)]
    #[serde(rename_all = "snake_case")]
    enum Stage {
      PreRelease,
      Stable,
    }
    let stages: HashMap<Stage, u8> =
      from(json!({ "pre_release": "1", "stable": 2 })).unwrap();
    assert_eq!(stages[&Stage::PreRelease], 1);
    assert_eq!(stages[&Stage::Stable], 2);

    // A key which doesn't parse is an error naming the type.
    let err = from::<HashMap<u16, String>>(json!({ "nope": "x" }))
      .unwrap_err();
    assert!(err.to_string().contains("expected u16"), "{err}");
    assert!(
      from::<HashMap<Stage, u8>>(json!({ "beta": 1 })).is_err()
    );
  }

  /// A tuple or fixed size array reads as many entries as it has:
  /// more is an error (as in serde_json), not the rest dropped.
  #[test]
  fn extra_sequence_entries_are_an_error() {
    #[derive(Debug, Deserialize, PartialEq)]
    struct Pair(u8, u8);

    #[derive(Debug, Deserialize, PartialEq)]
    struct Fixed {
      pair: (u8, u8),
      key: [u8; 2],
    }

    assert!(from::<(u8, u8)>(json!([1, 2, 3])).is_err());
    assert!(from::<[u8; 2]>(json!([9, 8, 7, 6])).is_err());
    assert!(from::<Pair>(json!([1, 2, 3])).is_err());
    let err = from::<(u8, u8)>(json!("1,2,3")).unwrap_err();
    assert!(
      err.to_string().contains("expected fewer elements in array"),
      "{err}"
    );
    assert!(
      from::<Fixed>(json!({ "pair": [1, 2, 3], "key": [9, 8] }))
        .is_err()
    );

    // Exactly enough is fine, from an array or a string.
    assert_eq!(
      from::<Fixed>(json!({ "pair": "1, 2", "key": [9, 8] }))
        .unwrap(),
      Fixed {
        pair: (1, 2),
        key: [9, 8]
      }
    );
    assert_eq!(from::<Pair>(json!(["1", 2])).unwrap(), Pair(1, 2));
    // A Vec reads them all.
    assert_eq!(
      from::<Vec<u8>>(json!("1,2,3")).unwrap(),
      vec![1, 2, 3]
    );
  }

  #[test]
  fn coercion_errors_carry_no_values_after_redaction() {
    let err = from::<u16>(json!("hunter2secret")).unwrap_err();
    let message = crate::error::redact_serde_error(&err);
    assert!(!message.contains("hunter2secret"), "{message}");
    assert!(message.contains("expected u16"), "{message}");
  }
}
