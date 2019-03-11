//! This crate contains convenience functions for checking valid kerberos credentials.
//! It is a rough port of the [`cccolutils` python package](https://pagure.io/cccolutils).

use std::os::raw::c_char;

use std::ffi::CString;
use std::ffi::CStr;


extern "C" {
    fn get_username_for_realm_c(realm: *const c_char) -> *const c_char;
    fn free_username_c(username: *const c_char);
    fn has_credentials_c() -> i32;
}


/// Checks the name of the authenticated user for a given realm.
///
/// It will return `Some(username)` if there is an authenticated user for the
/// given realm, and `None` otherwise.
///
/// ```
/// let username = cccolutils::get_username(String::from("FEDORAPROJECT.ORG"));
/// ```
pub fn get_username(realm: String) -> Option<String> {
    let realm = CString::new(realm).unwrap();

    unsafe {
        let username = get_username_for_realm_c(realm.as_ptr());

        if username.is_null() {
            None
        } else {
            let user_string = CStr::from_ptr(username);
            let result = user_string.to_owned().into_string().unwrap();

            // this is necessary to prevent a memory leak (detected by leak sanitizer)
            free_username_c(username);

            Some(result)
        }
    }
}


/// Checks if there is any authenticated user for any realm.
///
/// ```
/// let authenticated = cccolutils::has_credentials();
/// ```
pub fn has_credentials() -> bool {
    unsafe {
        has_credentials_c() == 1
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    #[ignore]
    fn test_has_credentials() {
        // ignore this result, since it can fail. but it should't crash.
        assert_eq!(
            has_credentials(),
            true
        );
    }

    #[test]
    fn test_get_username() {
        // check if valid REALM and USERNAME were supplied via environment variables
        let (realm, username) = match (env::var("REALM"), env::var("USERNAME")) {
            (Ok(r), Ok(u)) => (r, u),
            (_, _) => {
                println!("No realm and username specified.");
                return;
            }
        };

        assert_eq!(
            get_username(realm),
            Some(username)
        );
    }

    #[test]
    fn fail_get_username() {
        // nobody should have a kerberos ticket for example.com
        assert_eq!(
            get_username(String::from("EXAMPLE.COM")),
            None
        );
    }
}
