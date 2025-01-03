use argon2::{password_hash::PasswordHasher, Argon2, Params};
use num_bigint::BigUint;
use num_traits::FromBytes;
use rand::rngs::OsRng;
use rand::RngCore;

pub struct KeyDerivation {
    salt: [u8; 16],
    params: Params,
}

impl KeyDerivation {
    pub fn new() -> Self {
        let params = Params::new(32 * 1024, 2, 1, Some(32)).expect("Invalid Argon2 parameters");

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        Self { salt, params }
    }

    pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], &'static str> {
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];

        if argon2
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .is_err()
        {
            return Err("Failed to derive key using Argon2");
        }

        Ok(key)
    }

    pub fn key_to_string(key: &[u8; 32]) -> String {
        let num = BigUint::from_bytes_be(key);
        num.to_string()
    }

    pub fn key_from_string(encoded: &str) -> Result<[u8; 32], &'static str> {
        let num = encoded
            .parse::<BigUint>()
            .map_err(|_| "Invalid key string format")?;

        let bytes = num.to_bytes_be();
        if bytes.len() != 32 {
            return Err("Invalid key length");
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    pub fn create_key_from_passphrase(&self, passphrase: &str) -> Result<[u8; 32], &'static str> {
        Self::derive_key(passphrase, &self.salt)
    }

    pub fn get_salt_as_number(&self) -> u128 {
        // Interpret salt as a big-endian u128
        u128::from_be_bytes(self.salt)
    }

    pub fn from_number_to_salt(number: u128) -> [u8; 16] {
        // Convert a number back into a byte array
        number.to_be_bytes()
    }
}
