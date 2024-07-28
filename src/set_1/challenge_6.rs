// Break repeating-key XOR
// https://cryptopals.com/sets/1/challenges/6
pub fn break_repeating_key_xor(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
  ciphertext
    .iter()
    .zip(key.iter().cycle())
    .map(|(&c, &k)| c ^ k)
    .collect()
}

pub fn find_repeating_key(ciphertext: Vec<Vec<u8>>) -> Vec<u8> {
  ciphertext
    .into_iter()
    .map(|block| {
      let (key, _) = single_byte_xor_cipher(&block);
      key
    })
    .collect()
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

pub fn transpose_blocks(ciphertext: &[u8], key_size: usize) -> Vec<Vec<u8>> {
  (0..key_size)
    .map(|i| ciphertext.iter().skip(i).step_by(key_size).cloned().collect())
    .collect()
}

pub fn find_key_size(ciphertext: &[u8]) -> usize {
  (2..40)
    .map(|key_size| {
      let total_score: f64 = (0..10)
        .flat_map(|i| {
          (i + 1..10).map(move |j| {
            let block1 = &ciphertext[i * key_size..(i + 1) * key_size];
            let block2 = &ciphertext[j * key_size..(j + 1) * key_size];
            hamming_distance(block1, block2) as f64 / key_size as f64
          })
        })
        .sum();
      (key_size, total_score / 45.0)
    })
    .min_by(|&(_, score1), &(_, score2)| score1.partial_cmp(&score2).unwrap())
    .map(|(keysize, _)| keysize)
    .unwrap_or(0)
}

pub fn hamming_distance(p1: &[u8], p2: &[u8]) -> usize {
  p1.iter()
    .zip(p2.iter())
    .map(|(&x, &y)| (x ^ y).count_ones() as usize)
    .sum()
}

pub fn decode_base64(s: &str) -> Option<Vec<u8>> {
  if s.len() % 4 != 0 {
    return None;
  }
  let padding = s.chars()
    .rev()
    .take_while(|&c| c == '=')
    .count();
  let n = s.len() - padding;
  let bytes: Vec<u8> = s.chars()
    .take(n)
    .filter_map(u8_from_base64)
    .collect();
  let decoded: Vec<u8> = bytes.chunks(4)
    .flat_map(|chunk| {
      let mut out = vec![
        (chunk[0] << 2) | (chunk[1] >> 4),
        (chunk[1] << 4) | (chunk.get(2).unwrap_or(&0) >> 2),
        (chunk.get(2).unwrap_or(&0) << 6) | chunk.get(3).unwrap_or(&0),
      ];
      out.truncate(chunk.len() - 1);
      out
    }).collect();
  Some(decoded)
}

fn u8_from_base64(c: char) -> Option<u8> {
  match c {
    'A'..='Z' => Some(c as u8 - b'A'),
    'a'..='z' => Some(26 + (c as u8 - b'a')),
    '0'..='9' => Some(52 + (c as u8 - b'0')),
    '+' => Some(62),
    '/' => Some(63),
    '\n' | '=' => None, // Skip '\n' or '='
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use std::fs;
  use std::path::Path;

  use crate::set_1::challenge_6::*;

  #[test]
  fn test_break_repeating_key_xor() {
    let path = Path::new("src/set_1/data/6.txt");
    let content = fs::read_to_string(path).expect("File not found!");
    let decoded_content = match decode_base64(&content) {
      Some(data) => data,
      None => panic!("Base64 decoding failed"),
    };
    let key_size = find_key_size(&decoded_content);
    let key = find_repeating_key(transpose_blocks(&decoded_content, key_size));
    assert_eq!(key, b"Terminator X: Bring the noise");
    let result = break_repeating_key_xor(&decoded_content, &key);
    assert_eq!(&result[0..33], b"I'm back and I'm ringin' the bell");
  }
}
