use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=src/extract.cpp");
    println!("cargo:rerun-if-env-changed=LLVM_SYS_140_PREFIX");
    let config = env::var_os("LLVM_SYS_140_PREFIX")
        .map(|p| PathBuf::from(p).join("bin/llvm-config"))
        .unwrap_or_else(|| "llvm-config-14".into());
    let query = |arg: &str| {
        let output = Command::new(&config)
            .arg(arg)
            .output()
            .expect("LLVM 14 llvm-config");
        assert!(output.status.success(), "llvm-config {arg} failed");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    };
    assert!(
        query("--version").starts_with("14."),
        "pangs-source requires Clang 14"
    );
    cc::Build::new()
        .cpp(true)
        .warnings(false)
        .std("c++17")
        .flag_if_supported("-fno-rtti")
        .include(query("--includedir"))
        .file("src/extract.cpp")
        .compile("pangs_source");
    println!("cargo:rustc-link-search=native={}", query("--libdir"));
    println!("cargo:rustc-link-lib=dylib=clang-cpp");
    let shared = Command::new(&config)
        .args(["--libnames", "--link-shared"])
        .output()
        .expect("LLVM shared library name");
    assert!(shared.status.success());
    for library in String::from_utf8(shared.stdout).unwrap().split_whitespace() {
        let name = library.strip_prefix("lib").unwrap_or(library);
        let name = name.split(".so").next().unwrap().trim_end_matches(".dylib");
        println!("cargo:rustc-link-lib=dylib={name}");
    }
}
