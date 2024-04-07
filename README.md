# Kerberos 5 Credentials Cache Collection Utilities (DEPRECATED)

[![crates.io](https://img.shields.io/crates/v/cccolutils.svg)](https://crates.io/crates/cccolutils/)
[![crates.io](https://img.shields.io/crates/d/cccolutils.svg)](https://crates.io/crates/cccolutils/)
[![crates.io](https://img.shields.io/crates/l/cccolutils.svg)](https://crates.io/crates/cccolutils/)
[![docs.rs](https://docs.rs/cccolutils/badge.svg)](https://docs.rs/cccolutils/)

**WARNING**: This crate is no longer actively maintained.

This package is a rough rust port of the
[`cccolutils` python package][cccolutils.py].

[cccolutils.py]: https://pagure.io/cccolutils

The C part is inspired by the CPython extension from this python package, with
some adaptations and fixes for all the memory leaks I could find (using valgrind
with a small C test program, and the leak sanitizer from nightly rust for the
rust code).

The available API is currently limited to the following three functions:

- `fn get_username_for_realm(realm: String) -> Result<Option<String>, String>`:
  determine the username of the authenticated user for a given realm
- `fn has_credentials() -> bool`: determine if there are any active
  authentication tickets for any realm
- `fn has_credentials_for_realm(realm: String) -> Result<bool, String>`:
  determine if there is an authenticated user for the given realm

The style of the C code is enforced with the uncrustify configuration in this
directory.

