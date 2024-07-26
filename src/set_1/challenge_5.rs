// Implement repeating-key XOR
// https://cryptopals.com/sets/1/challenges/5
pub fn implement_repeating_key_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
  plaintext
    .iter()
    .zip(key.iter().cycle())
    .map(|(&p, &k)| p ^ k)
    .collect()
}

#[cfg(test)]
mod tests {
  use crate::set_1::challenge_5::implement_repeating_key_xor;

  #[test]
  fn test_implement_repeating_key_xor() {
    let plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = b"ICE";
    let result = implement_repeating_key_xor(plaintext, key);
    let expected_hex = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(hex::encode(result), expected_hex);
  }
}
