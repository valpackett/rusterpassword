//! An implementation of the [Master Password algorithm](https://ssl.masterpasswordapp.com/algorithm.html).
//!
//! Don't forget to initialize libsodium before using.

extern crate libc;
extern crate secstr;
extern crate byteorder;
extern crate libsodium_sys as ffi;

use std::io;
use secstr::*;
use libc::size_t;
use byteorder::{BigEndian, WriteBytesExt};

/// Low level master key generation function (basically, scrypt).
pub fn gen_master_key_custom(password: SecStr, salt: SecStr, n: u64, r: u32, p: u32, result_len: usize) -> io::Result<SecStr> {
    let password_a = password.unsecure();
    let salt_a = salt.unsecure();
    let mut dst = Vec::<u8>::with_capacity(result_len);
    if unsafe {
        ffi::crypto_pwhash_scryptsalsa208sha256_ll(
            password_a.as_ptr(), password_a.len() as size_t,
            salt_a.as_ptr(), salt_a.len() as size_t,
            n, r, p,
            dst.as_mut_ptr(), result_len as size_t)
    } == 0 {
        unsafe { dst.set_len(result_len); }
        Ok(SecStr::new(dst))
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "Scrypt failed"))
    }
}

/// Generate a 512-bit (64-byte) master key.
pub fn gen_master_key(password: SecStr, name: &str) -> io::Result<SecStr> {
    let mut salt = vec![];
    salt.extend(b"com.lyndir.masterpassword");
    salt.write_u32::<BigEndian>(name.len() as u32).unwrap();
    salt.extend(name.bytes());
    gen_master_key_custom(password, SecStr::new(salt), 32768, 8, 2, 64)
}

/// Generate a 256-bit (32-byte) site seed.
pub fn gen_site_seed(master_key: SecStr, site_name: &str, counter: u32) -> io::Result<SecStr> {
    let mut msg = vec![];
    msg.extend(b"com.lyndir.masterpassword");
    msg.write_u32::<BigEndian>(site_name.len() as u32).unwrap();
    msg.extend(site_name.bytes());
    msg.write_u32::<BigEndian>(counter).unwrap();
    let mut dst = Vec::<u8>::with_capacity(32);
    if unsafe {
        ffi::crypto_auth_hmacsha256(
            dst.as_mut_ptr() as *mut [u8; 32],
            msg.as_ptr(), msg.len() as size_t,
            master_key.unsecure().as_ptr() as *mut [u8; 32])
    } == 0 {
        unsafe { dst.set_len(32); }
        Ok(SecStr::new(dst))
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "HMAC-SHA-256 failed"))
    }
}

// pub fn gen_site_password(site_seed: SecStr, template: &[String]) -> SecStr {
// }

#[cfg(test)]
mod tests {
    use super::*;
    use secstr::*;

    #[test]
    fn test_everything() {
        let master_key = gen_master_key(SecStr::from("hunter2"), "UserName").unwrap();
        let site_seed = gen_site_seed(master_key, "site", 1).unwrap();
    }
}
