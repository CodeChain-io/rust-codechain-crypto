// Copyright 2018 Kodebox, Inc.
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

use digest::Digest;
use primitives::{H160, H256};
use ripemd160::Ripemd160;
use sha1::Sha1;
use sha2::Sha256;
use sha3::Keccak256;

/// RIPEMD160
#[inline]
pub fn ripemd160<T: AsRef<[u8]>>(s: T) -> H160 {
    let input = s.as_ref();
    let mut hasher = Ripemd160::new();
    hasher.input(input);
    let mut array: [u8; 20] = [0; 20];
    array.copy_from_slice(&hasher.result());
    H160(array)
}

/// SHA-1
#[inline]
pub fn sha1<T: AsRef<[u8]>>(s: T) -> H160 {
    let input = s.as_ref();
    let mut hasher = Sha1::new();
    hasher.input(input);
    let mut array: [u8; 20] = [0; 20];
    array.copy_from_slice(&hasher.result());
    H160(array)
}

/// SHA-256
#[inline]
pub fn sha256<T: AsRef<[u8]>>(s: T) -> H256 {
    let input = s.as_ref();
    let mut hasher = Sha256::new();
    hasher.input(input);
    let mut array: [u8; 32] = [0; 32];
    array.copy_from_slice(&hasher.result());
    H256(array)
}

/// KECCAK256
#[inline]
pub fn keccak256<T: AsRef<[u8]>>(s: T) -> H256 {
    let input = s.as_ref();
    let mut hasher = Keccak256::new();
    hasher.input(input);
    let mut array: [u8; 32] = [0; 32];
    array.copy_from_slice(&hasher.result());
    H256(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn _ripemd160() {
        let expected = H160::from_str("108f07b8382412612c048d07d13f814118445acd").unwrap();
        let result = ripemd160(b"hello");
        assert_eq!(result, expected);
    }

    #[test]
    fn _sha1() {
        let expected = H160::from_str("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").unwrap();
        let result = sha1(b"hello");
        assert_eq!(result, expected);
    }

    #[test]
    fn _sha256() {
        let expected = H256::from_str("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824").unwrap();
        let result = sha256(b"hello");
        assert_eq!(result, expected);
    }

    #[test]
    fn _keccak256() {
        let expected = H256::from_str("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8").unwrap();
        let result = keccak256(b"hello");
        assert_eq!(result, expected);
    }
}
