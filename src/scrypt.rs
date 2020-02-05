// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

use scrypt::{scrypt, ScryptParams};

use crate::error::ScryptError;
use crate::{Password, KEY_LENGTH, KEY_LENGTH_AES};

// Do not move Password. It will make debugger print the password.
pub fn derive_key(pass: &Password, salt: &[u8; 32], n: u32, p: u32, r: u32) -> Result<(Vec<u8>, Vec<u8>), ScryptError> {
    // sanity checks
    let log_n = (32 - n.leading_zeros() - 1) as u8;
    if u32::from(log_n) >= r * 16 {
        return Err(ScryptError::InvalidN)
    }

    if u64::from(p) > ((u64::from(u32::max_value()) - 1) * 32) / (128 * u64::from(r)) {
        return Err(ScryptError::InvalidP)
    }

    let mut derived_key = vec![0u8; KEY_LENGTH];
    let scrypt_params = ScryptParams::new(log_n, r, p)?;
    scrypt(pass.as_bytes(), salt, &scrypt_params, &mut derived_key)?;
    let derived_right_bits = &derived_key[0..KEY_LENGTH_AES];
    let derived_left_bits = &derived_key[KEY_LENGTH_AES..KEY_LENGTH];
    Ok((derived_right_bits.to_vec(), derived_left_bits.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::Password;

    #[test]
    fn scrypt_test() {
        let mut password = Password("rust-crypto-codechain");
        let mut salt = [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let mut n: u32 = 8;
        let mut p: u32 = 16;
        let mut r: u32 = 8;

        let mut result = derive_key(&password, &salt, n, p, r).unwrap();
        let mut right_bits = [229, 222, 150, 129, 167, 152, 151, 149, 110, 135, 118, 252, 139, 12, 227, 29];
        let mut left_bits = [111, 69, 216, 187, 101, 33, 114, 185, 126, 184, 57, 98, 243, 60, 174, 249];
        assert_eq!(&result.0[..], right_bits);
        assert_eq!(&result.1[..], left_bits);


        password = Password("Codechain and Foundry");
        salt = [0; 32];
        n = 16;
        p = 1;
        r = 1;

        result = derive_key(&password, &salt, n, p, r).unwrap();
        right_bits = [144, 79, 151, 99, 185, 187, 191, 74, 135, 222, 178, 102, 32, 179, 194, 170];
        left_bits = [179, 96, 63, 181, 115, 192, 159, 237, 20, 181, 18, 253, 164, 77, 199, 136];
        assert_eq!(&result.0[..], right_bits);
        assert_eq!(&result.1[..], left_bits);
    }
}
