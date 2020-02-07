# crypto [![Build Status](https://travis-ci.com/CodeChain-io/rust-codechain-crypto.svg?branch=master)](https://travis-ci.com/CodeChain-io/rust-codechain-crypto) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
The crypto library used by [CodeChain](https://github.com/CodeChain-io/codechain).

## Usage

#### The block cipher modes of operation

CodeChain is using two modes of operation: the [AES-256-CBC](https://tools.ietf.org/html/rfc3602) mode for the network module and [AES-128-CTR](https://tools.ietf.org/html/rfc3686#section-2.1) mode for the keystore. 

AES-256-CBC mode example:
```rust 
extern crate codechain_crypto as ccrypto;

use ccrypto::aes;
use ccrypto::error::SymmError;
use primitives::H256;
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;

let message = "rust-codechain-crypto";
let mut key = H256([0; 32]);

// An initialization vector can be used as a random value.
let mut rng = OsRng::new().ok().unwrap();
rng.fill_bytes(&mut key);
let iv = rng.gen();

let encrypted_data = encrypt(message.as_bytes(), &key, &iv).ok().unwrap();
let decrypted_data = decrypt(&encrypted_data[..], &key, &iv).ok().unwrap();

assert_ne!(message.as_bytes(), &encrypted_data[..]);
assert_eq!(message.as_bytes(), &decrypted_data[..]);
```

AES-128-CTR mode example:
```rust
extern crate codechain_crypto as ccrypto;

use ccrypto::aes;
use ccrypto::error::SymmError;
use primitives::H256;

let plaintext = "CodeChain and Foundry"'

// In CTR, key (`k`) length and initialization vector (`iv`) length have to be 16 bytes each.
// An error is returned if the input lengths are invalid.
let key = [1; 16];
let iv = [1; 16];
let mut result = [0; 10];

let _ = encrypt_128_ctr(&key, &iv, &plaintext, &mut result);
assert_ne!(result, plaintext);

let ciphertext = result;
let _ = decrypt_128_ctr(&key, &iv, &ciphertext, &mut result);
assert_eq!(result, plaintext);
```

#### Hash functions
The list of hash functions provided is as follows: [RIPE Message Digest](https://en.wikipedia.org/wiki/RIPEMD), [Secure Hash Algorithms](https://en.wikipedia.org/wiki/Secure_Hash_Algorithms) and [BLAKE2](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2).

Hash function example:
```rust
extern crate codechain_crypto as ccrypto;

use ccrypto::hash::{keccak256, ripemd160, sha1, sha256};
use ccrypto::blake;
use primitives::{H128, H160, H256};

// RIPEMD-160
let mut expected = "c469c5f091dd3d24fc6a2c8b440baa0eba0b22e9".into();
let mut result = ripemd160(b"Hello, CodeChain");
assert_eq!(result, expected);

// SHA-1
expected = "1540596421c8c1318a511b0e7ba70675cec010fc".into();
result = sha1(b"Hello, Foundry");
assert_eq!(result, expected);

// SHA-2(SHA-256)
expected = "40d0f22f4ad2c2d53865d94ace0de55362aacf4a2039ea54a74822bcc7e4e170".into();
result = sha256(b"Hello, rust-codechain-crypto");
assert_eq!(result, expected);

// SHA-3(Keccak256)
expected = "2b10aa230e79a187f0b488fdfdcd97e9ac898f29676c45b4d12bd1bf61871d0e".into();
result = keccak256(b"CodeChain and Foundry");
assert_eq!(result, expected);

// BLAKE-2(Blake256)
expected = "0xb5a3b7c1929e3eb54385cf26f7962729a44ce679ad0591f17009712a8f8bd06e".into();
result = blake256(b"CodeChain's crypto library");
assert_eq!(result, expected);

// BLAKE256 with key
let hash1 = blake256_with_key([0u8; 0], &[0; 64]);
let hash2 = blake256_with_key([0u8; 0], &[1; 64]);
assert_ne!(hash1, hash2);
```

#### Password hashing: Scrypt

CodeChain is using [scrypt](https://en.wikipedia.org/wiki/Scrypt), which is a password-based [key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) for password hashing.

Scrypt example:
```rust
extern crate codechain_crypto as ccrypto;

use ccrypto::scrypt;
use ccrypto::error::ScryptError;
use ccrypto::password::Password;

// The string of characters to be hashed.
let password = Password("CodeChain and Foundry");

// A string of characters that modifies the hash to protect against Rainbow table attacks.
let salt = [0; 32];

// CPU/memory cost parameter.
let n = 16;

// Parallelization parameter
let p = 1;
// The blocksize parameter
let r = 1;

result = derive_key(&password, &salt, n, p, r).unwrap();
right_bits = [144, 79, 151, 99, 185, 187, 191, 74, 135, 222, 178, 102, 32, 179, 194, 170];
left_bits = [179, 96, 63, 181, 115, 192, 159, 237, 20, 181, 18, 253, 164, 77, 199, 136];
assert_eq!(&result.0[..], right_bits);
assert_eq!(&result.1[..], left_bits);
```

## Build

Download the package

```sh
git clone git@github.com:CodeChain-io/rust-codechain-crypto.git
cd rust-codechain-crypto
```

Build in dev mode

```sh
cargo build
```

Build in release mode

```sh
cargo build --release
```
This will produce an executable in the ./target/release directory.

## Test

Developers are strongly encouraged to write unit tests for new code and submit new unit tests for old code. Unit tests can be compiled and run with: `cargo test --all`.