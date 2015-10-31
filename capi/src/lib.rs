extern crate libc;
extern crate secstr;
extern crate rusterpassword;

use libc::*;
use std::ffi::*;
use secstr::*;
use rusterpassword::*;

#[no_mangle]
pub extern fn rusterpassword_gen_master_key(password_c: *const c_char, name_c: *const c_char) -> *mut SecStr {
    let password = SecStr::from(unsafe { assert!(!password_c.is_null()); CStr::from_ptr(password_c) }.to_bytes());
    let name = unsafe { assert!(!name_c.is_null()); CStr::from_ptr(name_c) }.to_str().unwrap();
    Box::into_raw(Box::new(gen_master_key(password, &name).unwrap()))
}

#[no_mangle]
pub extern fn rusterpassword_gen_site_seed(master_key_c: *const SecStr, site_name_c: *const c_char, counter: u32) -> *mut SecStr {
    let master_key = unsafe { assert!(!master_key_c.is_null()); &*master_key_c };
    let site_name = unsafe { assert!(!site_name_c.is_null()); CStr::from_ptr(site_name_c) }.to_str().unwrap();
    Box::into_raw(Box::new(gen_site_seed(master_key, &site_name, counter).unwrap()))
}

#[no_mangle]
pub extern fn rusterpassword_gen_site_password(site_seed_c: *const SecStr, templates_c: u32) -> *mut c_char {
    let site_seed = unsafe { assert!(!site_seed_c.is_null()); &*site_seed_c };
    let templates = match templates_c {
        10 => TEMPLATES_PIN,
        20 => TEMPLATES_BASIC,
        30 => TEMPLATES_SHORT,
        40 => TEMPLATES_MEDIUM,
        50 => TEMPLATES_LONG,
        60 => TEMPLATES_MAXIMUM,
        _  => panic!("Unknown templates")
    };
    CString::new(gen_site_password(site_seed, templates).unsecure()).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern fn rusterpassword_free_master_key(master_key: *mut SecStr) {
    Box::from_raw(master_key);
}

#[no_mangle]
pub unsafe extern fn rusterpassword_free_site_seed(master_key: *mut SecStr) {
    Box::from_raw(master_key);
}

#[no_mangle]
pub unsafe extern fn rusterpassword_free_site_password(site_password: *mut c_char) {
    CString::from_raw(site_password);
}
