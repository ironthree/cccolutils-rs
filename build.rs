extern crate cc;

fn main() {
    cc::Build::new().file("src/cccolutils.c").compile("cccolutils");

    println!("cargo:rustc-link-lib=krb5");
}
