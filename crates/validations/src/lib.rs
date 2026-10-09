//! # Input Validation Module
//!
//! This module provides validation functions for user inputs to prevent
//! invalid data from entering the system and improve security.

use std::sync::OnceLock;

use anyhow::{Context, anyhow};
use regex::Regex;

/// Options to validate input strings to have certain properties.
/// This ensures only valid data can enter the system.
///
/// ## Usage
///
/// ```
/// # use mogh_validations::{StringValidator, StringValidatorMatches};
/// # fn main() -> anyhow::Result<()> {
/// StringValidator::default()
///   .min_length(1)
///   .max_length(100)
///   .matches(StringValidatorMatches::Username)
///   .validate("admin@example.com")?;
/// # Ok(())
/// # }
/// ```
#[derive(Default)]
pub struct StringValidator {
  /// Specify the minimum length of string.
  /// Setting `0` will effectively skip this validation.
  pub min_length: usize,
  /// Specify max length of string, or None to allow arbitrary length.
  pub max_length: Option<usize>,
  /// Skip the control character check.
  /// Most values should not contain these by default.
  pub skip_control_check: bool,
  /// Specify a pattern to validate the string contents.
  pub matches: Option<StringValidatorMatches>,
}

impl StringValidator {
  /// Returns Ok if input passes validations, otherwise includes
  /// error with failure reason.
  pub fn validate(&self, input: &str) -> anyhow::Result<()> {
    // Count characters rather than bytes, so multi-byte (eg. unicode)
    // input is measured the way the error messages describe.
    let len = input.chars().count();

    if len < self.min_length {
      return Err(anyhow!(
        "Input too short. Must be at least {} characters.",
        self.min_length
      ));
    }

    if let Some(max_length) = self.max_length
      && len > max_length
    {
      return Err(anyhow!(
        "Input too long. Must be at most {max_length} characters."
      ));
    }

    if !self.skip_control_check {
      validate_no_control_chars(input)?;
    }

    if let Some(matches) = &self.matches {
      matches.validate(input)?
    }

    Ok(())
  }

  pub fn min_length(mut self, min_length: usize) -> StringValidator {
    self.min_length = min_length;
    self
  }

  pub fn max_length(
    mut self,
    max_length: impl Into<Option<usize>>,
  ) -> StringValidator {
    self.max_length = max_length.into();
    self
  }

  pub fn skip_control_check(mut self) -> StringValidator {
    self.skip_control_check = true;
    self
  }

  pub fn matches(
    mut self,
    matches: impl Into<Option<StringValidatorMatches>>,
  ) -> StringValidator {
    self.matches = matches.into();
    self
  }
}

pub enum StringValidatorMatches {
  /// - alphanumeric characters
  /// - underscores
  /// - hyphens
  /// - dots
  /// - @
  /// - not 24 hex digits, the shape of a MongoDB ObjectId: an app
  ///   looking a user up by "id or username" would take such a
  ///   name for another user's id.
  Username,
  /// - alphanumeric characters
  /// - underscores
  /// - not starting with a digit
  VariableName,
}

impl StringValidatorMatches {
  /// Returns Ok if input passes validations, otherwise includes
  /// error with failure reason.
  fn validate(&self, input: &str) -> anyhow::Result<()> {
    let validate = || match self {
      StringValidatorMatches::Username => {
        static USERNAME_REGEX: OnceLock<Regex> = OnceLock::new();
        let regex = USERNAME_REGEX.get_or_init(|| {
          Regex::new(r"^[a-zA-Z0-9._@-]+$")
            .expect("Failed to initialize username regex")
        });
        if !regex.is_match(input) {
          return Err(anyhow!(
            "Only alphanumeric characters, underscores, hyphens, dots, and @ are allowed"
          ));
        }
        if is_object_id(input) {
          return Err(anyhow!(
            "Cannot be 24 hex digits, the shape of an ObjectId"
          ));
        }
        Ok(())
      }

      StringValidatorMatches::VariableName => {
        static VARIABLE_NAME_REGEX: OnceLock<Regex> = OnceLock::new();
        let regex = VARIABLE_NAME_REGEX.get_or_init(|| {
          Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
            .expect("Failed to initialize variable name regex")
        });
        if regex.is_match(input) {
          Ok(())
        } else {
          Err(anyhow!(
            "Only alphanumeric characters and underscores are allowed"
          ))
        }
      }
    };
    validate().context("Invalid characters in input")
  }
}

/// Whether `input` parses as a MongoDB ObjectId: exactly the 24
/// hex digits (either case) `bson::oid::ObjectId::from_str`
/// accepts, without depending on bson.
fn is_object_id(input: &str) -> bool {
  input.len() == 24 && input.bytes().all(|b| b.is_ascii_hexdigit())
}

fn validate_no_control_chars(input: &str) -> anyhow::Result<()> {
  for (index, char) in input.chars().enumerate() {
    if char.is_control() {
      // The input is not echoed: it may be a secret (passwords are
      // validated with this), and the message ends up in responses
      // and logs, where raw control characters don't belong either.
      return Err(anyhow!(
        "Control character ({}) at index {index}",
        char.escape_unicode()
      ));
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn default_validator_accepts_empty_input() {
    StringValidator::default().validate("").unwrap();
  }

  #[test]
  fn min_length_boundaries() {
    let validator = StringValidator::default().min_length(3);
    assert!(validator.validate("ab").is_err());
    validator.validate("abc").unwrap();
    validator.validate("abcd").unwrap();
  }

  #[test]
  fn max_length_boundaries() {
    let validator = StringValidator::default().max_length(3);
    validator.validate("abc").unwrap();
    assert!(validator.validate("abcd").is_err());
    // None max length allows arbitrary length
    StringValidator::default()
      .max_length(None)
      .validate(&"a".repeat(10_000))
      .unwrap();
  }

  #[test]
  fn length_counts_chars_not_bytes() {
    // 'é' is 1 char but 2 bytes.
    let validator =
      StringValidator::default().min_length(2).max_length(3);
    assert!(validator.validate("é").is_err());
    validator.validate("ééé").unwrap();
    assert!(validator.validate("éééé").is_err());
  }

  #[test]
  fn control_chars_rejected_by_default() {
    let validator = StringValidator::default();
    assert!(validator.validate("hello\nworld").is_err());
    assert!(validator.validate("null\0byte").is_err());
    assert!(validator.validate("tab\there").is_err());
    validator.validate("plain text is fine").unwrap();
  }

  #[test]
  fn control_char_error_does_not_echo_the_input() {
    // Eg. a password, which must not reach responses or logs.
    let err = StringValidator::default()
      .validate("hunter2-secret\u{7}-password")
      .unwrap_err();
    let message = format!("{err:#}");
    assert!(!message.contains("hunter2"), "{message}");
    assert!(!message.contains('\u{7}'), "{message}");
    // Still says what and where.
    assert!(message.contains("index 14"), "{message}");
    assert!(message.contains("\\u{7}"), "{message}");
  }

  #[test]
  fn control_chars_allowed_when_skipped() {
    StringValidator::default()
      .skip_control_check()
      .validate("hello\nworld")
      .unwrap();
  }

  #[test]
  fn username_matcher() {
    let validator = StringValidator::default()
      .matches(StringValidatorMatches::Username);
    validator.validate("admin@example.com").unwrap();
    validator.validate("user_name-1.2").unwrap();
    assert!(validator.validate("").is_err());
    assert!(validator.validate("has space").is_err());
    assert!(validator.validate("semi;colon").is_err());
    assert!(validator.validate("path/traversal").is_err());
    assert!(validator.validate("dollar$sign").is_err());
  }

  /// Apps looking a user up by "id or username" take a name of
  /// this shape for another user's id, so it is refused, with or
  /// without a bson dependency.
  #[test]
  fn username_matcher_rejects_object_ids() {
    let validator = StringValidator::default()
      .matches(StringValidatorMatches::Username);
    for object_id in [
      "507f1f77bcf86cd799439011",
      "65f0c0ffee0123456789abcd",
      // ObjectId::from_str takes either case.
      "65F0C0FFEE0123456789ABCD",
      "65f0C0ffEE0123456789aBcD",
    ] {
      let err = validator.validate(object_id).unwrap_err();
      assert!(format!("{err:#}").contains("ObjectId"), "{err:#}");
    }
    // Same length but not all hex is fine
    validator.validate("z07f1f77bcf86cd799439011").unwrap();
    // Hex of another length is fine
    validator.validate("507f1f77bcf86cd79943901").unwrap();
    validator.validate("507f1f77bcf86cd7994390111").unwrap();
    validator.validate("deadbeef").unwrap();
  }

  #[test]
  fn variable_name_matcher() {
    let validator = StringValidator::default()
      .matches(StringValidatorMatches::VariableName);
    validator.validate("VALID_NAME").unwrap();
    validator.validate("_private2").unwrap();
    // Cannot start with digit
    assert!(validator.validate("2fast").is_err());
    assert!(validator.validate("has-hyphen").is_err());
    assert!(validator.validate("").is_err());
  }

  #[test]
  fn combined_validations() {
    let validator = StringValidator::default()
      .min_length(1)
      .max_length(100)
      .matches(StringValidatorMatches::Username);
    validator.validate("admin@example.com").unwrap();
    assert!(validator.validate("").is_err());
    assert!(validator.validate(&"a".repeat(101)).is_err());
    assert!(validator.validate("bad;input").is_err());
  }
}
