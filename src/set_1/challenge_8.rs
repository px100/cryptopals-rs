use std::collections::HashSet;
use std::fs;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DetectEcbError {
  #[error("Failed to read the file: {0}")]
  FileReadError(#[from] std::io::Error),
  #[error("Failed to decode hex: {0}")]
  HexDecodeError(#[from] hex::FromHexError),
}

// Detect AES in ECB mode
// https://cryptopals.com/sets/1/challenges/8
fn detect_aes_in_ecb_mode() -> Result<Option<String>, DetectEcbError> {
  let file_content = fs::read_to_string("src/set_1/data/8.txt")?;
  for line in file_content.lines() {
    let decoded = hex::decode(line)?;
    let chunks: Vec<_> = decoded.chunks(16).collect();
    let unique_chunks: HashSet<_> = chunks.iter().collect();
    if chunks.len() != unique_chunks.len() {
      return Ok(Some(line.to_string()));
    }
  }
  Ok(None)
}

#[cfg(test)]
mod tests {
  use crate::set_1::challenge_8::detect_aes_in_ecb_mode;

  #[test]
  fn test_detect_aes_in_ecb_mode() {
    let expected = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    match detect_aes_in_ecb_mode() {
      Ok(Some(line)) => assert_eq!(expected, line),
      Ok(None) => panic!("ECB mode was not detected, but it was expected."),
      Err(e) => panic!("An error occurred during ECB detection: {}", e),
    }
  }
}
