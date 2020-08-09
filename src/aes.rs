// Copyright 2018-2019 Kodebox, Inc.
// This file is part of CodeChain.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use aes::{Aes128, Aes256};
use block_modes::block_padding::Pkcs7;
use block_modes::InvalidKeyIvLength;
use block_modes::{BlockMode, Cbc};
use ctr::stream_cipher::generic_array::GenericArray;
use ctr::stream_cipher::{NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek};
use primitives::H256;

use super::error::SymmError;


type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type Aes128Ctr = ctr::Ctr128<Aes128>;

// AES-256/CBC/Pkcs encryption.
pub fn encrypt(data: &[u8], key: &H256, iv: &u128) -> Result<Vec<u8>, InvalidKeyIvLength> {
    let cipher = Aes256Cbc::new_var(key.as_ref(), &iv.to_be_bytes())?;
    let result = cipher.encrypt_vec(data);

    Ok(result)
}

// AES-256/CBC/Pkcs decryption.
pub fn decrypt(encrypted_data: &[u8], key: &H256, iv: &u128) -> Result<Vec<u8>, InvalidKeyIvLength> {
    let cipher = Aes256Cbc::new_var(key.as_ref(), &iv.to_be_bytes())?;
    let result = cipher.decrypt_vec(&encrypted_data.to_vec()).unwrap();

    Ok(result)
}

/// Encrypt a message (CTR mode).
///
/// Key (`k`) length and initialisation vector (`iv`) length have to be 16 bytes each.
/// An error is returned if the input lengths are invalid.
pub fn encrypt_128_ctr(k: &[u8], iv: &[u8], plain: &[u8], dest: &mut [u8]) -> Result<(), SymmError> {
    let mut cipher = Aes128Ctr::new(&GenericArray::from_slice(k), &GenericArray::from_slice(iv));
    dest.copy_from_slice(plain);
    cipher.apply_keystream(dest);
    Ok(())
}

/// Decrypt a message (CTR mode).
///
/// Key (`k`) length and initialisation vector (`iv`) length have to be 16 bytes each.
/// An error is returned if the input lengths are invalid.
pub fn decrypt_128_ctr(k: &[u8], iv: &[u8], encrypted: &[u8], dest: &mut [u8]) -> Result<(), SymmError> {
    let mut cipher = Aes128Ctr::new(&GenericArray::from_slice(k), &GenericArray::from_slice(iv));
    dest.copy_from_slice(encrypted);
    cipher.seek(0);
    cipher.apply_keystream(dest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::rngs::OsRng;
    use rand::Rng;
    use rand::RngCore;

    #[test]
    fn aes256_with_random_key_and_iv() {
        let message = "0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                       0123456789abcdefghijklmnopqrstubewxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        let mut key = H256([0; 32]);

        // In a real program, the key and iv may be determined
        // using some other mechanism. If a password is to be used
        // as a key, an algorithm like PBKDF2, Bcrypt, or Scrypt (all
        // supported by Rust-Crypto!) would be a good choice to derive
        // a password. For the purposes of this example, the key and
        // iv are just random values.
        let mut rng = OsRng::new().ok().unwrap();
        rng.fill_bytes(key.as_mut());
        let iv = rng.gen();

        let encrypted_data = encrypt(message.as_bytes(), &key, &iv).ok().unwrap();
        let decrypted_data = decrypt(&encrypted_data[..], &key, &iv).ok().unwrap();

        assert_eq!(message.as_bytes(), &decrypted_data[..]);
    }

    #[test]
    fn short_input() {
        let input = vec![130, 39, 16];

        let mut key = H256([0; 32]);

        let mut rng = OsRng::new().unwrap();
        rng.fill_bytes(key.as_mut());
        let iv = rng.gen();

        let encrypted = encrypt(&input, &key, &iv).unwrap();
        let decrypted = decrypt(&encrypted, &key, &iv).unwrap();
        assert_eq!(input, decrypted);
    }

    #[test]
    fn aes_256_cbc_encrypt_decrypt() {
        let message = [1, 2, 3, 4, 5, 6, 7, 8];
        let key = H256([0; 32]);
        let iv = 0;

        let encrypted_data = encrypt(&message, &key, &iv).ok().unwrap();
        assert_eq!(encrypted_data, [45, 34, 87, 122, 38, 50, 190, 242, 253, 245, 138, 7, 196, 24, 58, 91]);

        let decrypted_data = decrypt(&encrypted_data[..], &key, &iv).ok().unwrap();
        assert_eq!(message, &decrypted_data[..]);
    }

    #[test]
    fn aes_128_ctr_encrypt_decrypt() {
        let plaintext = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let key = [1; 16];
        let iv = [1; 16];
        let mut dest = [0; 10];

        let _ = encrypt_128_ctr(&key, &iv, &plaintext, &mut dest);
        assert_eq!(dest, [94, 118, 231, 156, 139, 128, 146, 51, 129, 171]);

        let ciphertext = dest;
        let _ = decrypt_128_ctr(&key, &iv, &ciphertext, &mut dest);
        assert_eq!(plaintext, dest);
    }
}
