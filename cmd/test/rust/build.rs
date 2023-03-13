fn main() {
    println!("cargo:rustc-link-search=native={}", "/Users/andrey.pshenkin/git/go/src/github.com/copperexchange/crypto-primitives-go/cmd/test/rust/target");
    // println!("cargo:rustc-link-lib=static={}", "awesome");
    println!("cargo:rustc-link-lib=static={}", "try");
   // println!("cargo:rustc-link-lib=awesome");
   //  println!("cargo:rustc-link-search=native={}", "/Users/andrey.pshenkin/git/go/src/github.com/copperexchange/crypto-primitives-go/cmd/test/rust/include");
}
