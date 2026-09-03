fn main() {
    println!("cargo:rustc-link-lib=wolfssl");
    if let Ok(prefix) = std::env::var("WOLFSSL_PREFIX") {
        println!("cargo:rustc-link-search=native={prefix}/lib");
        println!("cargo:include={prefix}/include");
    } else if cfg!(target_os = "linux") {
        if let Ok(output) = std::process::Command::new("pkg-config")
            .args(["--libs-only-L", "wolfssl"])
            .output()
        {
            for flag in String::from_utf8_lossy(&output.stdout).split_whitespace() {
                if let Some(path) = flag.strip_prefix("-L") {
                    println!("cargo:rustc-link-search=native={path}");
                }
            }
        }
    } else if cfg!(not(windows)) {
        println!("cargo:rustc-link-search=native=/opt/homebrew/opt/wolfssl/lib");
        println!("cargo:include=/opt/homebrew/opt/wolfssl/include");
    } else {
        println!("cargo:warning=WOLFSSL_PREFIX must be set on Windows");
    }
    println!("cargo:rerun-if-env-changed=WOLFSSL_PREFIX");
    println!("cargo:rerun-if-changed=build.rs");
}
