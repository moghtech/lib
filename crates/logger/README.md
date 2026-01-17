# Mogh Logger

Configurable application level logger. Handles internals for multiple output modes including open telemetry.

```rust
struct Config;

// Sets output to JSON
impl mogh_logger::LogConfig for Config {
  fn stdio(&self) -> mogh_logger::StdioLogMode {
    mogh_logger::StdioLogMode::Json
  }
}

// On application startup
mogh_logger::init(Config)?;
```