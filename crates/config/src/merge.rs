use serde::{Serialize, de::DeserializeOwned};

use crate::{Error, Result};

/// - Object is serde_json::Map<String, serde_json::Value>.
/// - Source will overide target.
/// - Will recurse when field is object if merge_object = true, otherwise object will be replaced.
/// - Will extend when field is array if extend_array = true, otherwise array will be replaced.
/// - Will return error when types on source and target fields do not match.
pub fn merge_objects(
  mut target: serde_json::Map<String, serde_json::Value>,
  source: serde_json::Map<String, serde_json::Value>,
  merge_nested: bool,
  extend_array: bool,
) -> Result<serde_json::Map<String, serde_json::Value>> {
  for (key, value) in source {
    let Some(curr) = target.remove(&key) else {
      target.insert(key, value);
      continue;
    };
    match curr {
      serde_json::Value::Object(target_obj) => {
        if !merge_nested {
          target.insert(key, value);
          continue;
        }
        match value {
          serde_json::Value::Object(source_obj) => {
            target.insert(
              key,
              serde_json::Value::Object(merge_objects(
                target_obj,
                source_obj,
                merge_nested,
                extend_array,
              )?),
            );
          }
          _ => {
            return Err(Error::ObjectFieldTypeMismatch {
              key,
              value,
            });
          }
        }
      }
      serde_json::Value::Array(mut target_arr) => {
        if !extend_array {
          target.insert(key, value);
          continue;
        }
        match value {
          serde_json::Value::Array(source_arr) => {
            target_arr.extend(source_arr);
            target.insert(key, serde_json::Value::Array(target_arr));
          }
          _ => {
            return Err(Error::ArrayFieldTypeMismatch { key, value });
          }
        }
      }
      _ => {
        target.insert(key, value);
      }
    }
  }
  Ok(target)
}

/// Source will overide target
pub fn merge_config<T: Serialize + DeserializeOwned>(
  target: T,
  source: T,
  merge_nested: bool,
  extend_array: bool,
) -> Result<T> {
  let serde_json::Value::Object(target) =
    serde_json::to_value(target)
      .map_err(|e| Error::SerializeJson { e })?
  else {
    return Err(Error::ValueIsNotObject);
  };
  let serde_json::Value::Object(source) =
    serde_json::to_value(source)
      .map_err(|e| Error::SerializeJson { e })?
  else {
    return Err(Error::ValueIsNotObject);
  };
  let object =
    merge_objects(target, source, merge_nested, extend_array)?;
  serde_json::from_value(serde_json::Value::Object(object))
    .map_err(|e| Error::ParseFinalJson { e })
}
