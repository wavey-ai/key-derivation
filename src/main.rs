use key_derivation::KeyDerivation;

fn main() -> Result<(), &'static str> {
    let kdf = KeyDerivation::new();
    let passphrase = "your secure passphrase";

    // Store salt as a number
    let salt_number = kdf.get_salt_as_number();
    println!("Salt as number: {}", salt_number);

    // Convert the number back into salt
    let retrieved_salt = KeyDerivation::from_number_to_salt(salt_number);

    // Derive key using the retrieved salt
    let key = KeyDerivation::derive_key(passphrase, &retrieved_salt)?;
    let key_number = KeyDerivation::key_to_string(&key);
    println!("Key as number: {}", key_number);

    println!("Derived key: {:x?}", key);
    Ok(())
}
