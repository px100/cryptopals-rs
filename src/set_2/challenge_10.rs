use std::fs::read_to_string;
use std::io::Error;
use std::path::PathBuf;

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, generic_array::GenericArray, KeyInit};
use base64::{Engine as _, engine::general_purpose};

pub const BLOCK_SIZE: usize = 16;

// Implement CBC mode
// https://cryptopals.com/sets/2/challenges/10
pub fn encrypt_cbc(data: &mut Vec<u8>, key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) {
  let mut padded_data = apply_pkcs7_padding(data, BLOCK_SIZE);
  let cipher = Aes128::new(&GenericArray::from(key));
  let mut previous_block = iv;
  padded_data.chunks_mut(BLOCK_SIZE).for_each(|block| {
    xor(block, &previous_block);
    let mut block_array = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut block_array);
    block.copy_from_slice(&block_array);
    previous_block.copy_from_slice(block);
  });
  *data = padded_data;
}

pub fn decrypt_cbc(data: &mut Vec<u8>, key: [u8; BLOCK_SIZE], iv: [u8; BLOCK_SIZE]) {
  let cipher = Aes128::new(&GenericArray::from(key));
  let mut previous_block = iv;
  data.chunks_mut(BLOCK_SIZE).for_each(|block| {
    let block_copy = block.to_vec();
    let mut block_array = GenericArray::clone_from_slice(block);
    cipher.decrypt_block(&mut block_array);
    xor(&mut block_array, &previous_block);
    block.copy_from_slice(&block_array);
    previous_block.copy_from_slice(&block_copy);
  });
  *data = remove_pkcs7_padding(data);
}

#[inline]
pub fn xor(buf1: &mut [u8], buf2: &[u8]) {
  buf1.iter_mut().zip(buf2.iter()).for_each(|(x, &y)| *x ^= y);
}

#[inline]
pub fn apply_pkcs7_padding(data: &[u8], block_size: usize) -> Vec<u8> {
  let padding_size = block_size - (data.len() % block_size);
  data.iter().cloned().chain(vec![padding_size as u8; padding_size].into_iter()).collect()
}

#[inline]
pub fn remove_pkcs7_padding(data: &[u8]) -> Vec<u8> {
  let padding_size = *data.last().unwrap() as usize;
  data[..data.len() - padding_size].to_vec()
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use crate::set_2::challenge_10::*;

  fn read_base64_encoded_file(filename: PathBuf) -> Result<Vec<u8>, Error> {
    read_to_string(&filename)
      .map(|content| {
        general_purpose::STANDARD
          .decode(content.split_whitespace().collect::<String>())
          .map_err(|e| {
            println!("Failed to decode base64: {}", e);
            Error::new(std::io::ErrorKind::InvalidData, "Base64 decode error")
          })
      })
      .and_then(|result| result)
  }

  #[test]
  fn test_empty_data() {
    let mut data = vec![];
    let key: [u8; BLOCK_SIZE] = *b"YELLOW SUBMARINE";
    let iv = [0_u8; BLOCK_SIZE];
    encrypt_cbc(&mut data, key, iv);
    decrypt_cbc(&mut data, key, iv);
    assert_eq!(data, vec![]);
  }

  #[test]
  fn test_cbc_mode_with_file() {
    let path = Path::new("src/set_2/data/10.txt");
    let data = read_base64_encoded_file(path.to_path_buf()).expect("Failed to read and decode the file");
    let key: [u8; BLOCK_SIZE] = *b"YELLOW SUBMARINE";
    let iv = [0_u8; BLOCK_SIZE];
    let mut decrypted_data = data.clone();
    decrypt_cbc(&mut decrypted_data, key, iv);
    let decrypted_string = String::from_utf8(decrypted_data).expect("Failed to convert to String");
    assert!(decrypted_string.starts_with("I'm back and I'm ringin' the bell"));
  }

  #[test]
  fn test_cbc_encryption_decryption() {
    let mut data = vec![
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 2, 3, 4, 5, 6, 7, 8, 9, 10,
      11, 12, 13, 14, 15, 16, 3, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 2, 2, 3,
      4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];
    let original_data = data.clone();
    let key: [u8; BLOCK_SIZE] = *b"YELLOW SUBMARINE";
    let iv = [0_u8; BLOCK_SIZE];
    encrypt_cbc(&mut data, key, iv);
    decrypt_cbc(&mut data, key, iv);
    assert_eq!(original_data, data);
  }

  #[test]
  fn test_non_multiple_block_size() {
    let mut data = vec![1, 2, 3, 4, 5];
    let original_data = data.clone();
    let key: [u8; BLOCK_SIZE] = *b"YELLOW SUBMARINE";
    let iv = [0_u8; BLOCK_SIZE];
    encrypt_cbc(&mut data, key, iv);
    decrypt_cbc(&mut data, key, iv);
    assert_eq!(original_data, data[..original_data.len()]);
  }
}
