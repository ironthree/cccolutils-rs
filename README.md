# Kerberos 5 Credentials Cache Collection Utilities

This package is a rough rust port of the
[`cccolutils` python package][cccolutils.py].

[cccolutils.py]: https://pagure.io/cccolutils

The C part is inspired by the CPython extension from this python package, with
some adaptations and fixes for all the memory leaks I could find (using valgrind
with a small C test program, and the leak sanitizer from nightly rust for the
rust code).

The available API is limited to the following functions:

- `fn get_username(realm: String) -> Option<String>`: determine the username
  of the authenticated user for a given realm
- `fn has_credentials() -> bool`: determine if there are any active
  authentication tickets for any realm

