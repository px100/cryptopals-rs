// Fixed XOR
// https://cryptopals.com/sets/1/challenges/2
pub fn fixed_xor(a: &[u8], b: &[u8]) -> Vec<u8> {
  a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
  use crate::set_1::challenge_2::fixed_xor;

  #[test]
  fn test_fixed_xor() {
    let buf1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let buf2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
    let result = fixed_xor(&buf1, &buf2);
    assert_eq!(hex::encode(result), String::from("746865206b696420646f6e277420706c6179"));
  }
}
