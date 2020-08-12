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

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Scrypt(e: ScryptError) {
            cause(e)
            from()
        }
        Symm(e: SymmError) {
            cause(e)
            from()
        }
        ZeroIterations {
            description("Iterations' value should not be zero")
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ScryptError {
        // log(N) < r / 16
        InvalidN {
            display("Invalid N argument of the scrypt encryption")
        }
        // p <= (2^31-1 * 32)/(128 * r)
        InvalidP {
            display("Invalid p argument of the scrypt encryption")
        }
        InvalidOutputLen {
            display("Invalid length of output")
        }
        InvalidParams {
            display("Invalid parameters")
        }
    }
}

#[allow(deprecated)]
mod errors {
    use crate::error::ScryptError;

    quick_error! {
        #[derive(Debug)]
        pub enum SymmError wraps PrivSymmErr {
            RustCrypto(e: block_modes::InvalidKeyIvLength) {
                display("symmetric crypto error")
                    from()
            }
            Ring(e: ring::error::Unspecified) {
                display("symmetric crypto error")
                    cause(e)
                    from()
            }
            Offset(x: usize) {
                display("offset {} greater than slice length", x)
            }
        }
    }

    impl From<ring::error::Unspecified> for SymmError {
        fn from(e: ring::error::Unspecified) -> SymmError {
            SymmError(PrivSymmErr::Ring(e))
        }
    }

    impl From<block_modes::InvalidKeyIvLength> for SymmError {
        fn from(e: block_modes::InvalidKeyIvLength) -> SymmError {
            SymmError(PrivSymmErr::RustCrypto(e))
        }
    }

    impl From<scrypt::errors::InvalidOutputLen> for ScryptError {
        fn from(_e: scrypt::errors::InvalidOutputLen) -> ScryptError {
            ScryptError::InvalidOutputLen
        }
    }

    impl From<scrypt::errors::InvalidParams> for ScryptError {
        fn from(_e: scrypt::errors::InvalidParams) -> ScryptError {
            ScryptError::InvalidParams
        }
    }
}
pub use self::errors::SymmError;
