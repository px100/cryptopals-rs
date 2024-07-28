// Implement PKCS#7 padding
// https://cryptopals.com/sets/2/challenges/9
pub fn implement_pkcs7_padding(data: &[u8], block_size: usize) -> Vec<u8> {
  let padding_size = block_size - (data.len() % block_size);
  data
    .iter()
    .cloned()
    .chain(vec![padding_size as u8; padding_size].into_iter())
    .collect()
}

#[cfg(test)]
mod tests {
  use crate::set_2::challenge_9::implement_pkcs7_padding;

  #[test]
  fn test_implement_pkcs7_padding() {
    let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();
    let result = implement_pkcs7_padding(b"YELLOW SUBMARINE", 20);
    assert_eq!(expected, result);
  }
}
