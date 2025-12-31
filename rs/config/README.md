# Mogh Config

Module for comprehensive loading of strongly typed configuration files using `std::fs` and `serde`.

- Supports parsing JSON, YAML, and TOML formatted files.
- Supports merging final configuration from multiple supplied files / directories.

```rust
#[derive(serde::Deserialize)]
struct Config {
  title: String,
  aliases: Vec<String>,
  endpoint: String,
  use_option: bool,
}

let config = (ConfigLoader {
  // Read config files from a directory
  paths: vec![PathBuf::from("./configs")],
  match_wildcards: vec![String::from("*config*.toml")],
  // It won't recurse into subdirectories unless they include '.configinclude' file
  include_file_name: ".configinclude",
  merge_nested: true,
  extend_array: true,
  debug_print: true,
})
.load::<Config>()
.expect("Failed to parse config from path");
```
