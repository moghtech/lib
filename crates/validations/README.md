# Mogh Validations

Utilities to validate incoming strings.

```rust
mogh_validations::StringValidator::default()
  .min_length(1)
  .max_length(100)
  .matches(StringValidatorMatches::Username)
  .validate("admin@example.com")?
```