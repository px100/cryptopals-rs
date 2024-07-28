use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AesEcbError {
  #[error("Input length is not a multiple of 16")]
  InvalidInputLength,
  #[error("UTF-8 conversion error: {0}")]
  Utf8ConversionError(#[from] std::string::FromUtf8Error),
}

// AES in ECB mode
// https://cryptopals.com/sets/1/challenges/7
pub fn aes_in_ecb_mode(key_stream: &[u8], text_stream: &[u8]) -> Result<Vec<u8>, AesEcbError> {
  if text_stream.len() % 16 != 0 {
    return Err(AesEcbError::InvalidInputLength);
  }
  let key = GenericArray::from_slice(key_stream);
  let cipher = Aes128::new(key);
  let mut blocks: Vec<GenericArray<u8, U16>> = text_stream
    .chunks(16)
    .map(GenericArray::clone_from_slice)
    .collect();
  cipher.decrypt_blocks(&mut blocks);
  Ok(blocks.into_iter().flatten().collect())
}

#[cfg(test)]
mod tests {
  use std::fs;

  use base64::Engine;

  use crate::set_1::challenge_7::{aes_in_ecb_mode, AesEcbError};

  #[test]
  fn test_aes_in_ecb_mode() -> Result<(), AesEcbError> {
    let file_content = fs::read_to_string("src/set_1/data/7.txt")
      .map(|s| s.replace('\n', ""))
      .expect("Failed to read file");
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
      .decode(file_content)
      .expect("Failed to decode base64 data");
    let key_stream = b"YELLOW SUBMARINE";
    let expected = fs::read_to_string("src/set_1/data/7s.txt")
      .expect("Failed to read file");
    let actual = aes_in_ecb_mode(key_stream, &bytes)?;
    let actual_str = String::from_utf8(actual)?;
    for (e, a) in expected.lines().zip(actual_str.lines()) {
      assert_eq!(e.trim(), a.trim(), "Decryption mismatch: expected '{}' but got '{}'", e.trim(), a.trim());
    }
    Ok(())
  }
}
