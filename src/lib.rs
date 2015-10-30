//! An implementation of the [Master Password algorithm](https://ssl.masterpasswordapp.com/algorithm.html).
//!
//! Don't forget to initialize libsodium before using.

extern crate libc;
extern crate secstr;
extern crate byteorder;
extern crate libsodium_sys as ffi;

use std::io;
use std::mem::uninitialized;
use secstr::*;
use libc::size_t;
use byteorder::{BigEndian, WriteBytesExt};

const SALT_PREFIX : &'static [u8] = b"com.lyndir.masterpassword";

pub const TEMPLATES_MAXIMUM : &'static [&'static str] = &["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"];
pub const TEMPLATES_LONG : &'static [&'static str] = &[
    "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv",
    "CvcvCvcvCvcvno", "CvccnoCvcvCvcv",
    "CvccCvcvnoCvcv", "CvccCvcvCvcvno",
    "CvcvnoCvccCvcv", "CvcvCvccnoCvcv",
    "CvcvCvccCvcvno", "CvcvnoCvcvCvcc",
    "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
    "CvccnoCvccCvcv", "CvccCvccnoCvcv",
    "CvccCvccCvcvno", "CvcvnoCvccCvcc",
    "CvcvCvccnoCvcc", "CvcvCvccCvccno",
    "CvccnoCvcvCvcc", "CvccCvcvnoCvcc",
    "CvccCvcvCvccno"
];
pub const TEMPLATES_MEDIUM : &'static [&'static str] = &["CvcnoCvc", "CvcCvcno"];
pub const TEMPLATES_SHORT : &'static [&'static str] = &["Cvcn"];
pub const TEMPLATES_BASIC : &'static [&'static str] = &["aaanaaan", "aannaaan", "aaannaaa"];
pub const TEMPLATES_PIN : &'static [&'static str] = &["nnnn"];

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

/// Generate a 512-bit (64-byte) master key using scrypt.
pub fn gen_master_key(password: SecStr, name: &str) -> io::Result<SecStr> {
    let mut salt = vec![];
    salt.extend(SALT_PREFIX);
    salt.write_u32::<BigEndian>(name.len() as u32).unwrap();
    salt.extend(name.bytes());
    gen_master_key_custom(password, SecStr::new(salt), 32768, 8, 2, 64)
}

/// Generate a 256-bit (32-byte) site seed using HMAC-SHA-256.
pub fn gen_site_seed(master_key: &SecStr, site_name: &str, counter: u32) -> io::Result<SecStr> {
    let mut msg = vec![];
    msg.extend(SALT_PREFIX);
    msg.write_u32::<BigEndian>(site_name.len() as u32).unwrap();
    msg.extend(site_name.bytes());
    msg.write_u32::<BigEndian>(counter).unwrap();
    let mut dst = Vec::<u8>::with_capacity(32);
    if unsafe {
        let mut state = uninitialized::<ffi::crypto_auth_hmacsha256_state>();
        let mut ret = 0;
        ret += ffi::crypto_auth_hmacsha256_init(
            &mut state,
            master_key.unsecure().as_ptr() as *const u8,
            master_key.unsecure().len() as size_t);
        ret += ffi::crypto_auth_hmacsha256_update(
            &mut state,
            msg.as_ptr(), msg.len() as size_t);
        ret += ffi::crypto_auth_hmacsha256_final(
            &mut state,
            dst.as_mut_ptr() as *mut [u8; 32]);
        ret
    } == 0 {
        unsafe { dst.set_len(32); }
        Ok(SecStr::new(dst))
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "HMAC-SHA-256 failed"))
    }
}

/// Generate a readable password from a site seed using templates.
pub fn gen_site_password(site_seed: SecStr, templates: &[&str]) -> SecStr {
    let site_seed_a = site_seed.unsecure();
    let template = templates[site_seed_a[0] as usize % templates.len()];
    let mut i = 0;
    SecStr::from(template.chars().map(|x| {
        i += 1;
        match x {
            'V' => b"AEIOU"[(site_seed_a[i] % 5) as usize],
            'C' => b"BCDFGHJKLMNPQRSTVWXYZ"[(site_seed_a[i] % 21) as usize],
            'v' => b"aeiou"[(site_seed_a[i] % 5) as usize],
            'c' => b"bcdfghjklmnpqrstvwxyz"[(site_seed_a[i] % 21) as usize],
            'A' => b"AEIOUBCDFGHJKLMNPQRSTVWXYZ"[(site_seed_a[i] % 26) as usize],
            'a' => b"AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz"[(site_seed_a[i] % 52) as usize],
            'n' => b"0123456789"[(site_seed_a[i] % 10) as usize],
            'o' => b"@&%?,=[]_:-+*$#!'^~;()/."[(site_seed_a[i] % 24) as usize],
            _   => b"AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()"[(site_seed_a[i] % 72) as usize]
        }
    }).collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secstr::*;

    #[test]
    fn test_pin() {
        let master_key = gen_master_key(SecStr::from("Correct Horse Battery Staple"), "Cosima Niehaus").unwrap();
        let site_seed = gen_site_seed(&master_key, "bank.com", 1).unwrap();
        assert_eq!(gen_site_password(site_seed, TEMPLATES_PIN).unsecure(), b"7404")
    }

    #[test]
    fn test_long() {
        let master_key = gen_master_key(SecStr::from("Correct Horse Battery Staple"), "Cosima Niehaus").unwrap();
        let site_seed = gen_site_seed(&master_key, "twitter.com", 5).unwrap();
        assert_eq!(gen_site_password(site_seed, TEMPLATES_LONG).unsecure(), b"Kiwe2^BecuRodw")
    }

    #[test]
    fn test_maximum() {
        let master_key = gen_master_key(SecStr::from("hunter2"), "UserName").unwrap();
        let site_seed = gen_site_seed(&master_key, "test", 1).unwrap();
        assert_eq!(gen_site_password(site_seed, TEMPLATES_MAXIMUM).unsecure(), b"e5:kl#V@0uAZ02xKUic5")
    }

}
