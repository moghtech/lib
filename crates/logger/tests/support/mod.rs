//! A local OTLP/HTTP collector stand in, shared by the export
//! tests (each its own test binary: [mogh_logger::init] installs
//! the process wide subscriber).

use std::{
  io::{BufRead as _, BufReader, Read as _, Write as _},
  net::TcpListener,
  sync::{Arc, Mutex},
};

use mogh_logger::{LogConfig, StdioLogMode};

pub struct Config {
  pub otlp_endpoint: String,
  pub targets: Vec<String>,
}

impl LogConfig for Config {
  fn stdio(&self) -> StdioLogMode {
    StdioLogMode::None
  }
  fn otlp_endpoint(&self) -> &str {
    &self.otlp_endpoint
  }
  fn targets(&self) -> &[String] {
    &self.targets
  }
}

/// A received export.
pub struct Export {
  pub request_line: String,
  /// Names lowercase.
  pub headers: Vec<(String, String)>,
  pub body: Vec<u8>,
}

impl Export {
  pub fn header(&self, name: &str) -> Option<&str> {
    self
      .headers
      .iter()
      .find(|(header, _)| header == name)
      .map(|(_, value)| value.as_str())
  }
}

/// Accepts OTLP/HTTP exports, answering each with an empty (ie.
/// fully accepted) response. An export is recorded before it is
/// answered, so it is visible once the exporter returns.
pub fn collector() -> (u16, Arc<Mutex<Vec<Export>>>) {
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let port = listener.local_addr().unwrap().port();
  let exports = Arc::new(Mutex::new(Vec::new()));
  let recorded = exports.clone();
  std::thread::spawn(move || {
    for stream in listener.incoming() {
      let Ok(mut stream) = stream else { continue };
      let mut reader = BufReader::new(stream.try_clone().unwrap());
      let mut request_line = String::new();
      reader.read_line(&mut request_line).unwrap();
      let mut headers = Vec::new();
      let mut content_length = 0;
      loop {
        let mut header = String::new();
        reader.read_line(&mut header).unwrap();
        let header = header.trim_end();
        if header.is_empty() {
          break;
        }
        if let Some((name, value)) = header.split_once(':') {
          let (name, value) =
            (name.to_ascii_lowercase(), value.trim().to_string());
          if name == "content-length" {
            content_length = value.parse().unwrap();
          }
          headers.push((name, value));
        }
      }
      let mut body = vec![0; content_length];
      reader.read_exact(&mut body).unwrap();
      recorded.lock().unwrap().push(Export {
        request_line: request_line.trim_end().to_string(),
        headers,
        body,
      });
      stream
        .write_all(
          b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
    }
  });
  (port, exports)
}
