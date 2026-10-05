# moghtech/lib

Collection of libraries used across Mogh apps.
These libraries handle common web app utilities, ensuring consistency across the Mogh application ecosystem.

## License

This project is licensed under the Mozilla Public License 2.0 (MPL-2.0).
Source: https://github.com/moghtech/lib

### Embedded APIs

- mogh_auth_client + mogh_auth_server

### Rust crates

- mogh_cache
- mogh_config
- mogh_encryption
- mogh_error
- mogh_logger
- mogh_pki
- mogh_rate_limit
- mogh_request_ip
- mogh_resolver
- mogh_secret_file
- mogh_server
- mogh_supporter
- mogh_validations

### Typescript packages

- mogh_auth_client ([auth/client/ts](auth/client/ts)): the auth api client.
- mogh_ui ([ui](ui)): common React components, the auth pages, the
  supporter badge.
- mogh_supporter ([supporter/ts](supporter/ts)): verifies supporter keys
  in the browser.

### Supporter keys

[supporter](supporter) is both sides of Mogh supporter keys implementation.
The Rust crate parses the key and serves the embedded api at `/supporter`,
over which the browser gets the key signed for its nonce and admins set a
key from the UI. The typescript package verifies the answer offline in
the browser, and `mogh_ui` renders the badge and the settings section.
A key unlocks nothing apart from the vanity features, no functional
features depend on it.

### Example app

[example](example) is a small app using all of the above (rust api, sqlite,
React + react-query UI), with api and browser test suites which verify the
libraries the way an app uses them. See its [README](example/README.md).
