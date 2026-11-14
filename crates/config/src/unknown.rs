//! The keys of the config files no field of the config type takes,
//! see [UnknownKey].
//!
//! The final deserialization runs through [Tracked], which records
//! the path of every value the config type skips: the derived
//! `Deserialize` of a struct without `deny_unknown_fields` reads a
//! key no field takes as `serde::de::IgnoredAny`. Each such path is
//! then looked up in the toml / yaml / json sources which hold it
//! ([CheckedSource]), so the warning names the file. The process
//! environment, env files and `cicada:` sources are no such sources:
//! keys other programs read are normal there (an env file shared
//! with a compose project, the secrets of an environment).

use std::{cell::RefCell, fmt, path::PathBuf};

use serde::de::{
  self, DeserializeSeed, Deserializer, EnumAccess, MapAccess,
  SeqAccess, VariantAccess, Visitor,
};

/// A key of a config file which no field of the config type takes:
/// a typo (`disable_user_registraton`), or a field which was renamed
/// or removed. It is ignored. Named by the file and the key's path,
/// never the value.
///
/// [ConfigLoader::load][crate::ConfigLoader::load] and
/// [load_with_env][crate::ConfigLoader::load_with_env] print a
/// warning for each one; [load_reporting][crate::ConfigLoader::load_reporting]
/// and [load_with_env_reporting][crate::ConfigLoader::load_with_env_reporting]
/// return them instead, for an app to log them its own way or a test
/// to assert a config file has none. Its `Display` is the warning's
/// text, without the `WARN` label.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownKey {
  /// The config file holding the key, as it was listed, found by a
  /// directory scan, or named by an include line.
  pub file: PathBuf,
  /// The key's path in the config, dot separated with list indices
  /// in brackets (`oidc.enabeld`, `providers[1].nmae`). A key of a
  /// table the file spells flat (`oidc_enabeld`, see
  /// [EnvSource::flat_prefix][crate::EnvSource::flat_prefix]) is
  /// named by its path in the table. An index is the entry's
  /// position in the file's own list.
  pub path: String,
}

impl fmt::Display for UnknownKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "{:?} | '{}' is no config field, it is ignored (a typo, or a renamed or removed field?)",
      self.file, self.path
    )
  }
}

/// A segment of a path into the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Segment {
  Key(String),
  Index(usize),
}

/// A path into the config, from its root.
pub(crate) type Path = Vec<Segment>;

/// The dot separated form of `path`, see [UnknownKey::path].
fn format_path(path: &[Segment]) -> String {
  let mut formatted = String::new();
  for segment in path {
    match segment {
      Segment::Key(key) => {
        if !formatted.is_empty() {
          formatted.push('.');
        }
        formatted.push_str(key);
      }
      Segment::Index(index) => {
        formatted.push_str(&format!("[{index}]"))
      }
    }
  }
  formatted
}

fn child(path: &[Segment], segment: Segment) -> Path {
  let mut child = path.to_vec();
  child.push(segment);
  child
}

/// A toml / yaml / json source, as it merged: its keys (flat ones
/// folded into their tables), each value which is no object or list
/// replaced by `null`, so no value of the file is kept to be named.
pub(crate) struct CheckedSource {
  file: PathBuf,
  keys: serde_json::Value,
}

impl CheckedSource {
  pub(crate) fn new(
    file: PathBuf,
    source: &serde_json::Map<String, serde_json::Value>,
  ) -> CheckedSource {
    CheckedSource {
      file,
      keys: keys_of(&serde_json::Value::Object(source.clone())),
    }
  }
}

/// `value` with each value which is no object or list replaced by
/// `null`.
fn keys_of(value: &serde_json::Value) -> serde_json::Value {
  match value {
    serde_json::Value::Object(object) => serde_json::Value::Object(
      object
        .iter()
        .map(|(key, value)| (key.clone(), keys_of(value)))
        .collect(),
    ),
    serde_json::Value::Array(items) => {
      serde_json::Value::Array(items.iter().map(keys_of).collect())
    }
    _ => serde_json::Value::Null,
  }
}

/// The keys of `sources` at the `ignored` paths of the merged
/// config, each once: by source, in the order they load, then in
/// the order the paths were found. A source which doesn't hold the
/// path (the key came from another kind of source) has nothing to
/// report.
///
/// An index of the merged config is no index of a file (a list
/// extended by several files): each entry of the file's list at
/// that place is looked at, and its own index named. An entry
/// holding the key is the same kind of entry, the key unknown in it
/// as well.
pub(crate) fn unknown_keys(
  sources: &[CheckedSource],
  ignored: &[Path],
) -> Vec<UnknownKey> {
  let mut unknown = Vec::<UnknownKey>::new();
  for source in sources {
    for path in ignored {
      let mut found = Vec::new();
      find(&source.keys, path, &mut Vec::new(), &mut found);
      for path in found {
        let key = UnknownKey {
          file: source.file.clone(),
          path: format_path(&path),
        };
        if !unknown.contains(&key) {
          unknown.push(key);
        }
      }
    }
  }
  unknown
}

/// The paths in `keys` matching `path`, any entry of a list for an
/// index.
fn find(
  keys: &serde_json::Value,
  path: &[Segment],
  at: &mut Path,
  found: &mut Vec<Path>,
) {
  let Some((segment, rest)) = path.split_first() else {
    found.push(at.clone());
    return;
  };
  match (segment, keys) {
    (Segment::Key(key), serde_json::Value::Object(object)) => {
      if let Some(keys) = object.get(key) {
        at.push(segment.clone());
        find(keys, rest, at, found);
        at.pop();
      }
    }
    (Segment::Index(_), serde_json::Value::Array(items)) => {
      for (index, keys) in items.iter().enumerate() {
        at.push(Segment::Index(index));
        find(keys, rest, at, found);
        at.pop();
      }
    }
    _ => {}
  }
}

/// A deserializer recording the path of every value deserialized as
/// ignored (`deserialize_ignored_any`) under it, and otherwise the
/// deserializer it wraps: the final deserialization runs through it
/// as through [mogh_env_parser::Lenient] alone.
pub(crate) struct Tracked<'a, D> {
  de: D,
  path: Path,
  ignored: &'a RefCell<Vec<Path>>,
}

impl<'a, D> Tracked<'a, D> {
  pub(crate) fn new(
    de: D,
    ignored: &'a RefCell<Vec<Path>>,
  ) -> Tracked<'a, D> {
    Tracked {
      de,
      path: Vec::new(),
      ignored,
    }
  }
}

macro_rules! forward_tracked {
  ($($method:ident($($arg:ident: $ty:ty),*);)*) => {
    $(
      fn $method<V: Visitor<'de>>(
        self,
        $($arg: $ty,)*
        visitor: V,
      ) -> Result<V::Value, Self::Error> {
        self.de.$method($($arg,)* Wrap {
          visitor,
          path: self.path,
          ignored: self.ignored,
        })
      }
    )*
  };
}

impl<'de, D: Deserializer<'de>> Deserializer<'de> for Tracked<'_, D> {
  type Error = D::Error;

  forward_tracked! {
    deserialize_any();
    deserialize_bool();
    deserialize_i8();
    deserialize_i16();
    deserialize_i32();
    deserialize_i64();
    deserialize_i128();
    deserialize_u8();
    deserialize_u16();
    deserialize_u32();
    deserialize_u64();
    deserialize_u128();
    deserialize_f32();
    deserialize_f64();
    deserialize_char();
    deserialize_str();
    deserialize_string();
    deserialize_bytes();
    deserialize_byte_buf();
    deserialize_option();
    deserialize_unit();
    deserialize_unit_struct(name: &'static str);
    deserialize_newtype_struct(name: &'static str);
    deserialize_seq();
    deserialize_tuple(len: usize);
    deserialize_tuple_struct(name: &'static str, len: usize);
    deserialize_map();
    deserialize_struct(
      name: &'static str,
      fields: &'static [&'static str]
    );
    deserialize_enum(
      name: &'static str,
      variants: &'static [&'static str]
    );
    deserialize_identifier();
  }

  fn deserialize_ignored_any<V: Visitor<'de>>(
    self,
    visitor: V,
  ) -> Result<V::Value, Self::Error> {
    if !self.path.is_empty() {
      self.ignored.borrow_mut().push(self.path);
    }
    self.de.deserialize_ignored_any(visitor)
  }

  fn is_human_readable(&self) -> bool {
    self.de.is_human_readable()
  }
}

/// The visitor of a [Tracked] value: what it is handed to visit (an
/// option's content, a list, a map, an enum) is tracked in turn.
struct Wrap<'a, V> {
  visitor: V,
  path: Path,
  ignored: &'a RefCell<Vec<Path>>,
}

macro_rules! forward_visit {
  ($($method:ident($ty:ty);)*) => {
    $(
      fn $method<E: de::Error>(
        self,
        v: $ty,
      ) -> Result<Self::Value, E> {
        self.visitor.$method(v)
      }
    )*
  };
}

impl<'de, V: Visitor<'de>> Visitor<'de> for Wrap<'_, V> {
  type Value = V::Value;

  fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.visitor.expecting(f)
  }

  forward_visit! {
    visit_bool(bool);
    visit_i8(i8);
    visit_i16(i16);
    visit_i32(i32);
    visit_i64(i64);
    visit_i128(i128);
    visit_u8(u8);
    visit_u16(u16);
    visit_u32(u32);
    visit_u64(u64);
    visit_u128(u128);
    visit_f32(f32);
    visit_f64(f64);
    visit_char(char);
    visit_str(&str);
    visit_borrowed_str(&'de str);
    visit_string(String);
    visit_bytes(&[u8]);
    visit_borrowed_bytes(&'de [u8]);
    visit_byte_buf(Vec<u8>);
  }

  fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
    self.visitor.visit_none()
  }

  fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
    self.visitor.visit_unit()
  }

  fn visit_some<D: Deserializer<'de>>(
    self,
    de: D,
  ) -> Result<Self::Value, D::Error> {
    self.visitor.visit_some(Tracked {
      de,
      path: self.path,
      ignored: self.ignored,
    })
  }

  fn visit_newtype_struct<D: Deserializer<'de>>(
    self,
    de: D,
  ) -> Result<Self::Value, D::Error> {
    self.visitor.visit_newtype_struct(Tracked {
      de,
      path: self.path,
      ignored: self.ignored,
    })
  }

  fn visit_seq<A: SeqAccess<'de>>(
    self,
    seq: A,
  ) -> Result<Self::Value, A::Error> {
    self.visitor.visit_seq(TrackedSeq {
      seq,
      path: self.path,
      ignored: self.ignored,
      index: 0,
    })
  }

  fn visit_map<A: MapAccess<'de>>(
    self,
    map: A,
  ) -> Result<Self::Value, A::Error> {
    self.visitor.visit_map(TrackedMap {
      map,
      path: self.path,
      ignored: self.ignored,
      key: None,
    })
  }

  fn visit_enum<A: EnumAccess<'de>>(
    self,
    data: A,
  ) -> Result<Self::Value, A::Error> {
    self.visitor.visit_enum(TrackedEnum {
      data,
      path: self.path,
      ignored: self.ignored,
    })
  }
}

/// A value at `path`, deserialized [Tracked].
struct TrackedSeed<'a, S> {
  seed: S,
  path: Path,
  ignored: &'a RefCell<Vec<Path>>,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de>
  for TrackedSeed<'_, S>
{
  type Value = S::Value;

  fn deserialize<D: Deserializer<'de>>(
    self,
    de: D,
  ) -> Result<Self::Value, D::Error> {
    self.seed.deserialize(Tracked {
      de,
      path: self.path,
      ignored: self.ignored,
    })
  }
}

struct TrackedSeq<'a, A> {
  seq: A,
  path: Path,
  ignored: &'a RefCell<Vec<Path>>,
  index: usize,
}

impl<'de, A: SeqAccess<'de>> SeqAccess<'de> for TrackedSeq<'_, A> {
  type Error = A::Error;

  fn next_element_seed<T: DeserializeSeed<'de>>(
    &mut self,
    seed: T,
  ) -> Result<Option<T::Value>, Self::Error> {
    let path = child(&self.path, Segment::Index(self.index));
    self.index += 1;
    self.seq.next_element_seed(TrackedSeed {
      seed,
      path,
      ignored: self.ignored,
    })
  }

  fn size_hint(&self) -> Option<usize> {
    self.seq.size_hint()
  }
}

struct TrackedMap<'a, A> {
  map: A,
  path: Path,
  ignored: &'a RefCell<Vec<Path>>,
  /// The key of the value to come.
  key: Option<String>,
}

impl<'de, A: MapAccess<'de>> MapAccess<'de> for TrackedMap<'_, A> {
  type Error = A::Error;

  fn next_key_seed<K: DeserializeSeed<'de>>(
    &mut self,
    seed: K,
  ) -> Result<Option<K::Value>, Self::Error> {
    self.key = None;
    self.map.next_key_seed(CaptureKey {
      seed,
      key: &mut self.key,
    })
  }

  fn next_value_seed<V: DeserializeSeed<'de>>(
    &mut self,
    seed: V,
  ) -> Result<V::Value, Self::Error> {
    let key = self.key.take().unwrap_or_default();
    let path = child(&self.path, Segment::Key(key));
    self.map.next_value_seed(TrackedSeed {
      seed,
      path,
      ignored: self.ignored,
    })
  }

  fn size_hint(&self) -> Option<usize> {
    self.map.size_hint()
  }
}

struct TrackedEnum<'a, A> {
  data: A,
  path: Path,
  ignored: &'a RefCell<Vec<Path>>,
}

impl<'a, 'de, A: EnumAccess<'de>> EnumAccess<'de>
  for TrackedEnum<'a, A>
{
  type Error = A::Error;
  type Variant = TrackedVariant<'a, A::Variant>;

  fn variant_seed<V: DeserializeSeed<'de>>(
    self,
    seed: V,
  ) -> Result<(V::Value, Self::Variant), Self::Error> {
    let mut variant = None;
    let (value, access) = self.data.variant_seed(CaptureKey {
      seed,
      key: &mut variant,
    })?;
    // An externally tagged variant's content is under its name,
    // `{ "Variant": { .. } }`.
    let path = match variant {
      Some(variant) => child(&self.path, Segment::Key(variant)),
      None => self.path,
    };
    Ok((
      value,
      TrackedVariant {
        access,
        path,
        ignored: self.ignored,
      },
    ))
  }
}

struct TrackedVariant<'a, X> {
  access: X,
  path: Path,
  ignored: &'a RefCell<Vec<Path>>,
}

impl<'de, X: VariantAccess<'de>> VariantAccess<'de>
  for TrackedVariant<'_, X>
{
  type Error = X::Error;

  fn unit_variant(self) -> Result<(), Self::Error> {
    self.access.unit_variant()
  }

  fn newtype_variant_seed<T: DeserializeSeed<'de>>(
    self,
    seed: T,
  ) -> Result<T::Value, Self::Error> {
    self.access.newtype_variant_seed(TrackedSeed {
      seed,
      path: self.path,
      ignored: self.ignored,
    })
  }

  fn tuple_variant<V: Visitor<'de>>(
    self,
    len: usize,
    visitor: V,
  ) -> Result<V::Value, Self::Error> {
    self.access.tuple_variant(
      len,
      Wrap {
        visitor,
        path: self.path,
        ignored: self.ignored,
      },
    )
  }

  fn struct_variant<V: Visitor<'de>>(
    self,
    fields: &'static [&'static str],
    visitor: V,
  ) -> Result<V::Value, Self::Error> {
    self.access.struct_variant(
      fields,
      Wrap {
        visitor,
        path: self.path,
        ignored: self.ignored,
      },
    )
  }
}

/// A map key (or an enum's variant), deserialized as it is, its text
/// kept in `key`.
struct CaptureKey<'k, S> {
  seed: S,
  key: &'k mut Option<String>,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de>
  for CaptureKey<'_, S>
{
  type Value = S::Value;

  fn deserialize<D: Deserializer<'de>>(
    self,
    de: D,
  ) -> Result<Self::Value, D::Error> {
    self.seed.deserialize(KeyDeserializer { de, key: self.key })
  }
}

struct KeyDeserializer<'k, D> {
  de: D,
  key: &'k mut Option<String>,
}

macro_rules! forward_key {
  ($($method:ident($($arg:ident: $ty:ty),*);)*) => {
    $(
      fn $method<V: Visitor<'de>>(
        self,
        $($arg: $ty,)*
        visitor: V,
      ) -> Result<V::Value, Self::Error> {
        self.de.$method($($arg,)* KeyVisitor {
          visitor,
          key: self.key,
        })
      }
    )*
  };
}

impl<'de, D: Deserializer<'de>> Deserializer<'de>
  for KeyDeserializer<'_, D>
{
  type Error = D::Error;

  forward_key! {
    deserialize_any();
    deserialize_bool();
    deserialize_i8();
    deserialize_i16();
    deserialize_i32();
    deserialize_i64();
    deserialize_i128();
    deserialize_u8();
    deserialize_u16();
    deserialize_u32();
    deserialize_u64();
    deserialize_u128();
    deserialize_f32();
    deserialize_f64();
    deserialize_char();
    deserialize_str();
    deserialize_string();
    deserialize_bytes();
    deserialize_byte_buf();
    deserialize_option();
    deserialize_unit();
    deserialize_unit_struct(name: &'static str);
    deserialize_newtype_struct(name: &'static str);
    deserialize_seq();
    deserialize_tuple(len: usize);
    deserialize_tuple_struct(name: &'static str, len: usize);
    deserialize_map();
    deserialize_struct(
      name: &'static str,
      fields: &'static [&'static str]
    );
    deserialize_enum(
      name: &'static str,
      variants: &'static [&'static str]
    );
    deserialize_identifier();
    deserialize_ignored_any();
  }

  fn is_human_readable(&self) -> bool {
    self.de.is_human_readable()
  }
}

/// Keeps the text of the key it visits.
struct KeyVisitor<'k, V> {
  visitor: V,
  key: &'k mut Option<String>,
}

macro_rules! capture_visit {
  ($($method:ident($ty:ty);)*) => {
    $(
      fn $method<E: de::Error>(
        self,
        v: $ty,
      ) -> Result<Self::Value, E> {
        *self.key = Some(v.to_string());
        self.visitor.$method(v)
      }
    )*
  };
}

impl<'de, V: Visitor<'de>> Visitor<'de> for KeyVisitor<'_, V> {
  type Value = V::Value;

  fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.visitor.expecting(f)
  }

  capture_visit! {
    visit_bool(bool);
    visit_i8(i8);
    visit_i16(i16);
    visit_i32(i32);
    visit_i64(i64);
    visit_i128(i128);
    visit_u8(u8);
    visit_u16(u16);
    visit_u32(u32);
    visit_u64(u64);
    visit_u128(u128);
    visit_f32(f32);
    visit_f64(f64);
    visit_char(char);
    visit_str(&str);
    visit_borrowed_str(&'de str);
  }

  fn visit_string<E: de::Error>(
    self,
    v: String,
  ) -> Result<Self::Value, E> {
    *self.key = Some(v.clone());
    self.visitor.visit_string(v)
  }

  fn visit_bytes<E: de::Error>(
    self,
    v: &[u8],
  ) -> Result<Self::Value, E> {
    *self.key = Some(String::from_utf8_lossy(v).into_owned());
    self.visitor.visit_bytes(v)
  }

  fn visit_borrowed_bytes<E: de::Error>(
    self,
    v: &'de [u8],
  ) -> Result<Self::Value, E> {
    *self.key = Some(String::from_utf8_lossy(v).into_owned());
    self.visitor.visit_borrowed_bytes(v)
  }

  fn visit_byte_buf<E: de::Error>(
    self,
    v: Vec<u8>,
  ) -> Result<Self::Value, E> {
    *self.key = Some(String::from_utf8_lossy(&v).into_owned());
    self.visitor.visit_byte_buf(v)
  }

  fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
    self.visitor.visit_none()
  }

  fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
    self.visitor.visit_unit()
  }

  fn visit_some<D: Deserializer<'de>>(
    self,
    de: D,
  ) -> Result<Self::Value, D::Error> {
    self.visitor.visit_some(de)
  }

  fn visit_newtype_struct<D: Deserializer<'de>>(
    self,
    de: D,
  ) -> Result<Self::Value, D::Error> {
    self.visitor.visit_newtype_struct(de)
  }

  fn visit_seq<A: SeqAccess<'de>>(
    self,
    seq: A,
  ) -> Result<Self::Value, A::Error> {
    self.visitor.visit_seq(seq)
  }

  fn visit_map<A: MapAccess<'de>>(
    self,
    map: A,
  ) -> Result<Self::Value, A::Error> {
    self.visitor.visit_map(map)
  }

  fn visit_enum<A: EnumAccess<'de>>(
    self,
    data: A,
  ) -> Result<Self::Value, A::Error> {
    self.visitor.visit_enum(data)
  }
}
