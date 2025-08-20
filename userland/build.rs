//
// Build script for XDR userland
// Generates FFI bindings from shared header and compiles C helper functions
//

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../shared/xdr_shared.h");
    println!("cargo:rerun-if-changed=c/xdr_uapi.c");

    // Skip Windows-specific compilation on non-Windows platforms for development
    if cfg!(not(target_os = "windows")) {
        // Create a dummy bindings file for development/testing
        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        std::fs::write(
            out_path.join("xdr_bindings.rs"),
            "// Dummy bindings for non-Windows development\npub const XDR_ABI_VERSION: u32 = 1;\n"
        ).expect("Failed to write dummy bindings");
        
        // Output version information
        println!("cargo:rustc-env=XDR_BUILD_TIMESTAMP={}", 
                 std::time::SystemTime::now()
                     .duration_since(std::time::UNIX_EPOCH)
                     .unwrap()
                     .as_secs());
        
        // Get git commit hash if available
        if let Ok(output) = std::process::Command::new("git")
            .args(&["rev-parse", "--short", "HEAD"])
            .output()
        {
            if output.status.success() {
                let git_hash = String::from_utf8_lossy(&output.stdout);
                println!("cargo:rustc-env=XDR_GIT_HASH={}", git_hash.trim());
            } else {
                println!("cargo:rustc-env=XDR_GIT_HASH=unknown");
            }
        } else {
            println!("cargo:rustc-env=XDR_GIT_HASH=unknown");
        }
        
        return;
    }

    // Windows-specific build logic
    // Get the OUT_DIR for generated files
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Configure and generate bindings
    let bindings = bindgen::Builder::default()
        // Input header file
        .header("../shared/xdr_shared.h")
        
        // Define Windows kernel mode symbols for userland compilation
        .clang_arg("-DWIN32")
        .clang_arg("-D_WIN32")
        .clang_arg("-D_WINDOWS")
        .clang_arg("-DUNICODE")
        .clang_arg("-D_UNICODE")
        
        // Include Windows SDK headers path (adjust as needed)
        .clang_arg("-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/shared")
        .clang_arg("-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um")
        .clang_arg("-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/winrt")
        
        // Generate bindings for XDR types only
        .allowlist_type("XDR_.*")
        .allowlist_var("XDR_.*")
        .allowlist_function("XdrGetAbiVersion")
        .allowlist_function("xdr_abi_version")
        
        // Derive common traits
        .derive_default(true)
        .derive_debug(true)
        .derive_copy(true)
        .derive_eq(true)
        .derive_partialeq(true)
        
        // Layout tests
        .layout_tests(true)
        
        // Generate!
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to $OUT_DIR/bindings.rs
    bindings
        .write_to_file(out_path.join("xdr_bindings.rs"))
        .expect("Couldn't write bindings!");

    // Compile C helper functions
    cc::Build::new()
        .file("c/xdr_uapi.c")
        .include("../shared")
        .define("WIN32", None)
        .define("_WIN32", None)
        .define("_WINDOWS", None)
        .define("UNICODE", None)
        .define("_UNICODE", None)
        .compile("xdr_uapi");

    // Link against Windows libraries
    println!("cargo:rustc-link-lib=kernel32");
    println!("cargo:rustc-link-lib=user32");
    println!("cargo:rustc-link-lib=advapi32");
    println!("cargo:rustc-link-lib=ws2_32");
    println!("cargo:rustc-link-lib=ntdll");
    println!("cargo:rustc-link-lib=psapi");
    println!("cargo:rustc-link-lib=version");
    println!("cargo:rustc-link-lib=wintrust");
    println!("cargo:rustc-link-lib=crypt32");

    // Additional libraries for specific features
    #[cfg(feature = "etw")]
    {
        println!("cargo:rustc-link-lib=tdh");
        println!("cargo:rustc-link-lib=evntrace");
    }

    #[cfg(feature = "wmi")]
    {
        println!("cargo:rustc-link-lib=ole32");
        println!("cargo:rustc-link-lib=oleaut32");
    }

    // Output version information
    println!("cargo:rustc-env=XDR_BUILD_TIMESTAMP={}", 
             std::time::SystemTime::now()
                 .duration_since(std::time::UNIX_EPOCH)
                 .unwrap()
                 .as_secs());
    
    // Get git commit hash if available
    if let Ok(output) = std::process::Command::new("git")
        .args(&["rev-parse", "--short", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_hash = String::from_utf8_lossy(&output.stdout);
            println!("cargo:rustc-env=XDR_GIT_HASH={}", git_hash.trim());
        } else {
            println!("cargo:rustc-env=XDR_GIT_HASH=unknown");
        }
    } else {
        println!("cargo:rustc-env=XDR_GIT_HASH=unknown");
    }
}