//! This crate contains convenience functions for checking valid kerberos credentials.
//! It is a rough port of the [`cccolutils` python package](https://pagure.io/cccolutils).

use std::os::raw::c_char;

use std::ffi::CString;
use std::ffi::CStr;


extern "C" {
    fn get_username_for_realm_c(realm: *const c_char) -> *const c_char;
    fn free_char_array_c(char_array: *const c_char);
    fn has_credentials_c() -> i32;
    fn has_credentials_for_realm_c(realm: *const c_char) -> i32;
}


/// This helper function attempts to convert a `String` to an `Ok(CString)`,
/// and returns an `Err(String)` if something goes wrong.
fn c_string_from_string(string: String) -> Result<CString, String> {
    match CString::new(string) {
        Ok(c_string) => Ok(c_string),
        Err(error) => Err(format!("Failed to encode String as CString: {:?}", error))
    }
}


/// This helper function attempts to convert a `*const c_char` to an `Ok(String)`,
/// and returns an `Err(String)` if something goes wrong.
fn string_from_char_ptr(char_array: *const c_char) -> Result<String, String> {
    if char_array.is_null() {
        return Err(String::from("Attempted to convert a NULL string value to a String."));
    }

    let c_string = unsafe { CStr::from_ptr(char_array) };

    let string = c_string.to_owned().into_string();
    unsafe { free_char_array_c(char_array) };

    match string {
        Ok(result) => Ok(result),
        Err(error) => Err(format!("Failed to decode char array: {:?}", error))
    }
}


/// Checks the name of the authenticated user for a given realm.
///
/// It will return `Ok(Some(username))` if there is an authenticated user for the
/// given realm, and `Ok(None)` otherwise.
///
/// `Err()` values are returned when string conversions fail.
///
/// ```
/// let username = cccolutils::get_username_for_realm(
///     String::from("FEDORAPROJECT.ORG")
/// ).unwrap();
/// ```
pub fn get_username_for_realm(realm: String) -> Result<Option<String>, String> {
    let realm = c_string_from_string(realm)?;

    let username = unsafe { get_username_for_realm_c(realm.as_ptr()) };

    if username.is_null() {
        Ok(None)
    } else {
        match string_from_char_ptr(username) {
            Ok(result) => Ok(Some(result)),
            Err(error) => Err(error)
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


/// Checks if there is an authenticated user for the given realm.
///
/// It will return `Ok(true)` if there is an authenticated user,
/// and `Ok(false)` otherwise.
///
/// `Err()` values are returned when string conversions fail.
///
/// ```
/// let authenticated_for_realm = cccolutils::has_credentials_for_realm(
///     String::from("FEDORAPROJECT.ORG")
/// ).unwrap();
/// ```
pub fn has_credentials_for_realm(realm: String) -> Result<bool, String> {
    let realm = c_string_from_string(realm)?;

    Ok(unsafe { has_credentials_for_realm_c(realm.as_ptr()) == 1 })
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
    fn test_has_credentials_for_realm() {
        let realm = match env::var("REALM") {
            Ok(realm) => realm,
            _ => {
                println!("No realm specified.");
                return;
            }
        };

        assert_eq!(
            has_credentials_for_realm(realm),
            Ok(true)
        );

        println!("Successfully checked credentials.");
    }

    #[test]
    fn fail_has_credentials_for_realm() {
        // nobody should have a kerberos ticket for example.com

        assert_eq!(
            has_credentials_for_realm(String::from("EXAMPLE.COM")),
            Ok(false)
        );

        println!("Successfully determined no authentication.");
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
