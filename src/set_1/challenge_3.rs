// Single-byte XOR cipher
// https://cryptopals.com/sets/1/challenges/3
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

#[cfg(test)]
mod tests {
  use crate::set_1::challenge_3::single_byte_xor_cipher;

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

  #[test]
  fn test_single_byte_xor_cipher() {
    let hex_bytes = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let (key, result) = single_byte_xor_cipher(&hex_bytes);
    assert_eq!(key, 88);
  }
}
