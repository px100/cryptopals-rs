use std::fs;
use std::path::Path;

// Detect single-character XOR
// https://cryptopals.com/sets/1/challenges/4
pub fn detect_single_character_xor(file_path: &Path) -> (u8, Vec<u8>) {
  fs::read_to_string(file_path)
    .expect("Failed to read file!")
    .lines()
    .filter_map(|line| {
      let (key, res) = single_byte_xor_cipher(&hex_to_bytes(line));
      let score = score_text(&res);
      Some((key, res, score))
    })
    .max_by_key(|&(_, _, score)| score)
    .map(|(key, res, _)| (key, res))
    .unwrap_or((0, Vec::new()))
}

pub fn single_byte_xor_cipher(x: &[u8]) -> (u8, Vec<u8>) {
  (0..=255)
    .map(|key| {
      let result = xor(x, key);
      let score = score_text(&result);
      (key, result, score)
    })
    .max_by_key(|&(_, _, score)| score)
    .map(|(key, result, _)| (key, result))
    .unwrap_or((0, Vec::new()))
}

fn xor(input: &[u8], key: u8) -> Vec<u8> {
  input.iter().map(|&byte| byte ^ key).collect()
}

fn score_text(text: &[u8]) -> i32 {
  let common_letters = b"ETAOIN SHRDLUetaoin shrdlu";
  text.iter().filter(|&&c| common_letters.contains(&c)).count() as i32
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
  hex
    .as_bytes()
    .chunks(2)
    .map(|chunk| {
      let high = hex_char_to_byte(chunk[0]);
      let low = hex_char_to_byte(chunk[1]);
      (high << 4) | low
    })
    .collect()
}

fn hex_char_to_byte(hex_char: u8) -> u8 {
  match hex_char {
    b'0'..=b'9' => hex_char - b'0',
    b'a'..=b'f' => hex_char - b'a' + 10,
    b'A'..=b'F' => hex_char - b'A' + 10,
    _ => panic!("Invalid hex char: {}", hex_char),
  }
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use crate::set_1::challenge_4::detect_single_character_xor;

  #[test]
  fn test_detect_single_character_xor() {
    let path = Path::new("data/4.txt");
    let (key, result) = detect_single_character_xor(&path);
    assert_eq!(key, 53);
  }
}
