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
/// StringValidator::default()
///   .min_length(1)
///   .max_length(100)
///   .matches(StringValidatorMatches::Username)
///   .validate("admin@example.com")?
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
    let len = input.len();

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
  /// - No Object Ids
  Username,
  /// - alphanumeric characters
  /// - underscores
  VariableName,
  /// - http or https URL.
  HttpUrl,
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
        #[cfg(feature = "bson")]
        {
          use std::str::FromStr as _;
          if bson::oid::ObjectId::from_str(input).is_ok() {
            return Err(anyhow!("Cannot be valid ObjectId"));
          }
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

      StringValidatorMatches::HttpUrl => {
        if !input.starts_with("http://")
          && !input.starts_with("https://")
        {
          return Err(anyhow!(
            "Input must start with http:// or https://"
          ));
        }
        url::Url::parse(input)
          .context("Failed to parse input as URL")
          .map(|_| ())
      }
    };
    validate().context("Invalid characters in input")
  }
}

fn validate_no_control_chars(input: &str) -> anyhow::Result<()> {
  for (index, char) in input.chars().enumerate() {
    if char.is_control() {
      return Err(anyhow!(
        "Control character at index {index}. Input: \"{input}\""
      ));
    }
  }
  Ok(())
}
