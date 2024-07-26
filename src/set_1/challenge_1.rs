use base64::{Engine as _, engine::general_purpose};

// Convert hex to base64
// https://cryptopals.com/sets/1/challenges/1
pub fn convert_hex_to_base64(input: String) -> Result<String, hex::FromHexError> {
  Ok(general_purpose::STANDARD_NO_PAD.encode(&hex::decode(input)?))
}

#[cfg(test)]
mod tests {
  use crate::set_1::challenge_1::convert_hex_to_base64;

  #[test]
  fn test_convert_hex_to_base64() {
    let hex: String =
      "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".into();
    let base64: String =
      "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".into();
    let result = convert_hex_to_base64(hex);
    assert_eq!(result.unwrap(), base64);
  }
}
