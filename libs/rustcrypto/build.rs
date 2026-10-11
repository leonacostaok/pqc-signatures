// Exposes crate versions (from Cargo.lock), the rustc version and the build tag to the binary.
use std::{env, fs, path::Path, process::Command};

fn lock_version(lock: &str, name: &str) -> String {
    let mut found = false;
    for line in lock.lines() {
        let l = line.trim();
        if l == format!("name = \"{name}\"") {
            found = true;
        } else if found && l.starts_with("version = ") {
            return l.trim_start_matches("version = ").trim_matches('"').to_string();
        } else if l.starts_with("[[") {
            found = false;
        }
    }
    "unknown".to_string()
}

fn main() {
    let dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lock = fs::read_to_string(Path::new(&dir).join("Cargo.lock")).unwrap_or_default();
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-env-changed=PQC_BUILD_TAG");
    println!("cargo:rustc-env=ML_DSA_VERSION={}", lock_version(&lock, "ml-dsa"));
    println!("cargo:rustc-env=SLH_DSA_VERSION={}", lock_version(&lock, "slh-dsa"));
    println!("cargo:rustc-env=PQC_BUILD_TAG={}", env::var("PQC_BUILD_TAG").unwrap_or_else(|_| "base".into()));
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let v = Command::new(rustc).arg("--version").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    println!("cargo:rustc-env=RUSTC_VERSION_STR={v}");
}
