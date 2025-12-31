use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Serror {
  pub error: String,
  pub trace: Vec<String>,
}

impl From<&anyhow::Error> for Serror {
  fn from(e: &anyhow::Error) -> Serror {
    Serror {
      error: e.to_string(),
      trace: e.chain().skip(1).map(|e| e.to_string()).collect(),
    }
  }
}

impl From<anyhow::Error> for Serror {
  fn from(e: anyhow::Error) -> Serror {
    (&e).into()
  }
}
