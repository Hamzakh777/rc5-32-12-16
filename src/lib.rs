use std::convert::TryInto;

use errors::RC5Error;

mod errors;

// This is an implementation of RC5-32/12/16
// === W
// Two "word" input ( 32 * 2 bits )
// Two "word" output ( 32 * 2 bits )
// === R
// Allowed values between 0-255
// Higher number of rounds provides increased level of security
// S - expanded key table
// T - the size of table S
//
// Fast symmetric block cipher:
// - Same key is used for both encryption and decryption
// - Plaintext and ciphertext are fixed-length bit sequences (blocks)

// RC5 parameters
const W: usize = 32; // Word size in bits
const R: usize = 12; // Number of rounds
const B: usize = 16; // Key length in bytes
const T: usize = 2 * (R + 1); // Length of the subkey array -- 26 in our case

// These can be auto-calculated if we use a trait to deal with words of different size
const NUMBER_OF_BYTES_IN_WORD: u32 = 4;
const NUMBER_OF_WORDS_IN_KEY: u32 = 4;
const WORDS_SIZE_ZERO: u32 = 0u32;

// RC5 constants for 32-bit word size
const P32: u32 = 0xB7E15163;
const Q32: u32 = 0x9E3779B9;

/**
 * Key expansion algorithm
 *
 * RC5 performs a complex set of operations on the secret key to produce a total of T subkeys
 * Since two subkeys are used each round (subkeys[i] and subkeys[i+1]), and two subkeys are used on
 * an additional opration that is not part of any round, T = 2 * R + 2 = 2 ( R + 1 ).
 * Each subkey is one W bits length
 * The plain text is divided into two blocks A and B each of 32 bits
 * Two subkeys are generated S[0] and S[1] and they are added to A and B respectively
 */
pub fn expand_key(key: &Vec<u8>) -> Result<Vec<u32>, RC5Error> {
    if key.len() != B {
        return Err(RC5Error::InvalidKeyLength);
    }

    // 1. key representation
    // Generate a set of round keys from the user-supplied key.
    // the user Key is split into NUMBER_OF_WORDS_IN_KEY words, where each word is W bit long
    let mut words: Vec<u32> = vec![WORDS_SIZE_ZERO; NUMBER_OF_WORDS_IN_KEY as usize];
    let u = NUMBER_OF_BYTES_IN_WORD as usize;
    // we are using `rev` to ensure that the bytes of the key are processed form the last byte to the first byte
    // iterating over the key bytes in reverse order, shifting and combining them into 32-bit words.
    for i in (0..B).rev() {
        let current_word_index = i / u;
        words[current_word_index] =
            (words[current_word_index].wrapping_shl(8u32)).wrapping_add(key[i] as u32);
    }

    // 2. subkey array
    let mut subkeys = vec![WORDS_SIZE_ZERO; T];
    subkeys[0] = P32;
    for i in 1..T {
        subkeys[i] = subkeys[i - 1].wrapping_add(Q32);
    }

    // 3. Mixing in the secret key
    let mut subkeys_index = 0;
    let mut words_index = 0;
    let mut a = WORDS_SIZE_ZERO;
    let mut b = WORDS_SIZE_ZERO;
    let iterations = T * 3;
    for _ in 0..iterations {
        a = subkeys[subkeys_index]
            .wrapping_add(a.wrapping_add(b))
            .rotate_left(3);
        subkeys[subkeys_index] = a;
        b = words[words_index]
            .wrapping_add(a.wrapping_add(b))
            .rotate_left(a.wrapping_add(b) % W as u32);
        words[words_index] = b;
        // reset the indexes
        subkeys_index = (subkeys_index + 1) % T;
        words_index = (words_index + 1) % NUMBER_OF_WORDS_IN_KEY as usize;
    }

    Ok(subkeys)
}

/*
 * This function should return a cipher text for a given key and plaintext
 */
fn encode(key: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, RC5Error> {
    if plaintext.len() != (NUMBER_OF_BYTES_IN_WORD * 2) as usize {
        return Err(RC5Error::InvalidPlainTextLength);
    }

    let mut ciphertext = Vec::new();
    let expanded_key = expand_key(&key)?;

    // its safe to use unwrap here because we already verified the plaintext length
    let block: [u32; 2] = [
        u32::from_le_bytes(plaintext[0..4].try_into().unwrap()),
        u32::from_le_bytes(plaintext[4..8].try_into().unwrap()),
    ];

    let mut a = block[0].wrapping_add(expanded_key[0]);
    let mut b = block[1].wrapping_add(expanded_key[1]);

    // In each round:
    // Bitwise xor
    // left circular shit
    // addition to to the next subkey
    for i in 1..=R {
        a = a ^ b;
        a = a
            .rotate_left(b % W as u32)
            .wrapping_add(expanded_key[2 * i]);
        b = b ^ a;
        b = b
            .rotate_left(a % W as u32)
            .wrapping_add(expanded_key[2 * i + 1]);
    }

    a.to_le_bytes().map(|el| ciphertext.push(el));
    b.to_le_bytes().map(|el| ciphertext.push(el));

    Ok(ciphertext)
}

/*
 * This function should return a plaintext for a given key and ciphertext
 */
fn decode(key: Vec<u8>, ciphertext: Vec<u8>) -> Result<Vec<u8>, RC5Error> {
    if ciphertext.len() != (NUMBER_OF_BYTES_IN_WORD * 2) as usize {
        return Err(RC5Error::InvalidCypherTextLength);
    }

    let mut plaintext = Vec::new();

    let expanded_key = expand_key(&key)?;

    // its safe to use unwrap here because we already verified the plaintext length
    let block: [u32; 2] = [
        u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()),
        u32::from_le_bytes(ciphertext[4..8].try_into().unwrap()),
    ];

    let mut a = block[0];
    let mut b = block[1];

    for i in (1..=R).rev() {
        b = b
            .wrapping_sub(expanded_key[2 * i + 1])
            .rotate_right(a % W as u32)
            ^ a;
        a = a
            .wrapping_sub(expanded_key[2 * i])
            .rotate_right(b % W as u32)
            ^ b
    }

    a.wrapping_sub(expanded_key[0])
        .to_le_bytes()
        .map(|el| plaintext.push(el));
    b.wrapping_sub(expanded_key[1])
        .to_le_bytes()
        .map(|el| plaintext.push(el));

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];
        let res = encode(key, pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn encode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];
        let res = encode(key, pt).unwrap();
        assert!(&ct[..] == &res[..]);
    }

    #[test]
    fn decode_a() {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let res = decode(key, ct).unwrap();

        assert!(&pt[..] == &res[..]);
    }

    #[test]
    fn decode_b() {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let res = decode(key, ct).unwrap();
        assert!(&pt[..] == &res[..]);
    }
}
