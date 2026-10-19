fn main() {
    println!("cargo:rustc-link-arg-cdylib=-Wl,-soname,libnetd.so.1");
}
