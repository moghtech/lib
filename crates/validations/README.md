# Mogh Validations

Utilities to validate incoming strings.

```rust
mogh_validations::StringValidator::default()
  .min_length(1)
  .max_length(100)
  .matches(StringValidatorMatches::Username)
  .validate("admin@example.com")?
```

## Matchers

- `Username`: alphanumeric characters, underscores, hyphens, dots
  and `@`, and never 24 hex digits: that is the shape of a MongoDB
  ObjectId, which an app looking a user up by "id or username" would
  take for another user's id. Checked without depending on bson
  (2.0.0 removed the `bson` feature, which 1.x needed for this check).
- `VariableName`: alphanumeric characters and underscores, not
  starting with a digit.

2.0.0 removed `HttpUrl`: urls are validated where they are used, eg.
`mogh_auth_server::validations::validate_public_http_url`, which also
refuses credentials in the url.
