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
/// let username = cccolutils::get_username_for_realm(String::from("FEDORAPROJECT.ORG")).unwrap();
/// ```
pub fn get_username_for_realm(realm: String) -> Result<Option<String>, String> {
    let realm = match CString::new(realm) {
        Ok(realm) => realm,
        Err(error) => { return Err(format!("Failed to encode realm as C-string: {:?}", error)); }
    };

    unsafe {
        let username = get_username_for_realm_c(realm.as_ptr());

        if username.is_null() {
            Ok(None)
        } else {
            let user_string = CStr::from_ptr(username);
            let result = match user_string.to_owned().into_string() {
                Ok(result) => result,
                Err(error) => { return Err(format!("Failed to decode username C-string: {:?}", error)); }
            };

            // this is necessary to prevent a memory leak (detected by leak sanitizer)
            free_username_c(username);

            Ok(Some(result))
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
    fn test_has_credentials() {
        // this function will return either true or false. but it should't crash, ever

        if has_credentials() {
            println!("Successfully checked for valid credentials.");
        } else {
            println!("Successfully checked for no valid credentials.");
        }
    }

    #[test]
    fn test_get_username() {
        // check if valid REALM and KUSER were supplied via environment variables,
        // which means the test can check for meaningful results

        let (realm, username) = match (env::var("REALM"), env::var("KUSER")) {
            (Ok(r), Ok(u)) => (r, u),
            (_, _) => {
                println!("No realm and username specified.");
                return;
            }
        };

        assert_eq!(
            get_username_for_realm(realm).unwrap(),
            Some(username)
        );

        println!("Successfully determined username.");
    }

    #[test]
    fn fail_get_username() {
        // nobody should have a kerberos ticket for example.com

        assert_eq!(
            get_username_for_realm(String::from("EXAMPLE.COM")).unwrap(),
            None
        );

        println!("Successfully determined no username.");
    }
}
