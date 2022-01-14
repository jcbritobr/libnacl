fn main() {
    println!("cargo:rustc-link-search=native=lib/");
    println!("cargo:rustc-link-lib=static=nacl");
    println!("cargo:rustc-link-lib=static=randombytes");
}