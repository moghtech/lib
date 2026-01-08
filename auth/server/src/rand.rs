use rand::Rng as _;

pub fn random_string(length: usize) -> String {
  rand::rng()
    .sample_iter(&rand::distr::Alphanumeric)
    .take(length)
    .map(char::from)
    .collect()
}

pub fn random_bytes(length: usize) -> Vec<u8> {
  rand::rng()
    .sample_iter(&rand::distr::Alphanumeric)
    .take(length)
    .collect()
}
