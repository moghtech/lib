//! A local http/1.1 server for the tests of the request functions:
//! it records what it receives and answers as the test says,
//! including with a body which never ends.

use std::{
  io::{BufRead as _, BufReader, Read as _, Write as _},
  net::{TcpListener, TcpStream},
  sync::{Arc, Mutex},
};

/// A request as the server received it.
#[derive(Debug, Clone)]
pub struct Received {
  pub method: String,
  pub path: String,
  /// Lowercase names, in the order received.
  pub headers: Vec<(String, String)>,
  pub body: Vec<u8>,
}

impl Received {
  pub fn header(&self, name: &str) -> Option<&str> {
    self
      .headers
      .iter()
      .find(|(header, _)| header == name)
      .map(|(_, value)| value.as_str())
  }
}

/// What the server answers a request with.
pub enum Answer {
  /// The status line (eg. `200 OK`) and the body.
  Body(&'static str, Vec<u8>),
  /// The status line, and a chunked body which never ends.
  Endless(&'static str),
  /// `307 Temporary Redirect` to the url.
  Redirect(String),
}

pub type Requests = Arc<Mutex<Vec<Received>>>;

/// Serves on a local port until the test process ends. `answer`
/// gets each request and how many came before it. Returns the
/// address (`http://127.0.0.1:{port}`) and the requests received.
pub fn serve(
  answer: impl Fn(&Received, usize) -> Answer + Send + Sync + 'static,
) -> (String, Requests) {
  let listener = TcpListener::bind("127.0.0.1:0").unwrap();
  let address = format!("http://{}", listener.local_addr().unwrap());
  let requests = Requests::default();
  let answer = Arc::new(answer);
  let received = requests.clone();
  std::thread::spawn(move || {
    for stream in listener.incoming().flatten() {
      let answer = answer.clone();
      let received = received.clone();
      std::thread::spawn(move || {
        // A connection ends with an error when the client drops it.
        let _ = serve_connection(stream, &*answer, &received);
      });
    }
  });
  (address, requests)
}

/// Requests one after another on the connection (keep alive).
fn serve_connection(
  mut stream: TcpStream,
  answer: &dyn Fn(&Received, usize) -> Answer,
  received: &Mutex<Vec<Received>>,
) -> std::io::Result<()> {
  let mut reader = BufReader::new(stream.try_clone()?);
  loop {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
      return Ok(());
    }
    let mut request_line = line.split_whitespace();
    let method = request_line.next().unwrap_or_default().to_string();
    let path = request_line.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    loop {
      let mut line = String::new();
      reader.read_line(&mut line)?;
      let line = line.trim_end();
      if line.is_empty() {
        break;
      }
      if let Some((name, value)) = line.split_once(':') {
        headers.push((
          name.trim().to_ascii_lowercase(),
          value.trim().to_string(),
        ));
      }
    }
    let len = headers
      .iter()
      .find(|(name, _)| name == "content-length")
      .and_then(|(_, value)| value.parse().ok())
      .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body)?;
    let request = Received {
      method,
      path,
      headers,
      body,
    };
    let before = {
      let mut received = received.lock().unwrap();
      received.push(request.clone());
      received.len() - 1
    };
    match answer(&request, before) {
      Answer::Body(status, body) => {
        write!(
          stream,
          "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
          body.len()
        )?;
        if request.method != "HEAD" {
          stream.write_all(&body)?;
        }
      }
      Answer::Redirect(location) => {
        write!(
          stream,
          "HTTP/1.1 307 Temporary Redirect\r\nlocation: {location}\r\ncontent-length: 0\r\n\r\n"
        )?;
      }
      Answer::Endless(status) => {
        write!(
          stream,
          "HTTP/1.1 {status}\r\ntransfer-encoding: chunked\r\n\r\n"
        )?;
        let chunk = [b'x'; 16 * 1024];
        loop {
          write!(stream, "{:x}\r\n", chunk.len())?;
          stream.write_all(&chunk)?;
          stream.write_all(b"\r\n")?;
        }
      }
    }
  }
}
