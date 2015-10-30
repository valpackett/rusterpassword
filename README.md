# rusterpassword [![crates.io](https://img.shields.io/crates/v/rusterpassword.svg)](https://crates.io/crates/rusterpassword) [![Build Status](https://img.shields.io/travis/myfreeweb/rusterpassword.svg?style=flat)](https://travis-ci.org/myfreeweb/rusterpassword) [![API Docs](https://img.shields.io/badge/api-docs-yellow.svg?style=flat)](https://myfreeweb.github.io/autodocs/rusterpassword/rusterpassword) [![unlicense](https://img.shields.io/badge/un-license-green.svg?style=flat)](http://unlicense.org)

A [Rust] implementation of the [Master Password algorithm].

Uses [secstr] secure strings and [libsodium] through [sodiumoxide]'s underlying `libsodium-sys`.

[Rust]: https://www.rust-lang.org
[Master Password algorithm]: https://ssl.masterpasswordapp.com/algorithm.html
[secstr]: https://github.com/myfreeweb/secstr
[libsodium]: https://github.com/jedisct1/libsodium
[sodiumoxide]: https://github.com/dnaq/sodiumoxide

## Usage

```rust
extern crate secstr;
extern crate rusterpassword;
extern crate sodiumoxide;

use secstr::*;
use rusterpassword::*;

fn main() {
    sodiumoxide::init();
    let master_key = gen_master_key(SecStr::from("Correct Horse Battery Staple"), "Cosima Niehaus").unwrap();
    let site_seed = gen_site_seed(&master_key, "twitter.com", 5).unwrap();
    let password = gen_site_password(site_seed, TEMPLATES_MAXIMUM);
}
```

## Contributing

Please feel free to submit pull requests!
Bugfixes and simple non-breaking improvements will be accepted without any questions :-)

By participating in this project you agree to follow the [Contributor Code of Conduct](http://contributor-covenant.org/version/1/2/0/).

[The list of contributors is available on GitHub](https://github.com/myfreeweb/rusterpassword/graphs/contributors).

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](http://unlicense.org).
