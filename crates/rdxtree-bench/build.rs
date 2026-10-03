// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Compiles the frozen reference the benchmark measures against.
//!
//! The reference is C, so it needs a C compiler; the frozen copy, its
//! host stand-ins for the headers it includes, and the flags that make
//! the two comparable to a Rust contender all live beside it under
//! `src/old`.  Nothing here is linked into the kernel, and nothing else
//! in the workspace calls a second tool (ADR 0052).

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The translation units, relative to the crate.
const SOURCES: [&str; 3] = [
    "src/old/rdxtree.c",
    "src/old/shim/slab.c",
    "src/old/shim/bridge.c",
];

/// The archive the three compile into.
const LIB: &str = "rdxtree_bench_ref";

fn tool(var: &str, default: &str) -> OsString {
    env::var_os(var).unwrap_or_else(|| default.into())
}

fn run(program: &OsString, args: &[OsString]) {
    let status =
        Command::new(program)
            .args(args)
            .status()
            .unwrap_or_else(|e| {
                panic!("cannot run {}: {e}", program.to_string_lossy())
            });
    assert!(
        status.success(),
        "{} failed: {status}",
        program.to_string_lossy()
    );
}

fn probe(program: &OsString) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let cc = tool("CC", "cc");
    let ar = tool("AR", "ar");

    for program in [&cc, &ar] {
        assert!(
            probe(program),
            "{} is missing; the reference tree needs it",
            program.to_string_lossy()
        );
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/old");

    let source = manifest.join("src/old");
    let shim = source.join("shim/include");

    let cflags: Vec<OsString> = [
        "-std=gnu11",
        // The contender's assertions are off in this profile; the
        // reference's are too, or the two are not the same program.
        "-DNDEBUG",
        // The kernel builds the tree with 32-bit keys, and the bridge
        // refuses to compile without this.
        "-DRDXTREE_KEY_32",
        // A host binary is position-independent, unlike the kernel.
        "-fPIC",
        "-Wall",
        "-Werror=implicit-function-declaration",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();

    let mut cflags = cflags;
    cflags.push(optimisation());

    let objects = compile(&cc, &cflags, &manifest, &source, &shim, &out);

    let lib = out.join(format!("lib{LIB}.a"));
    let mut ar_args: Vec<OsString> =
        vec!["crs".into(), lib.as_os_str().into()];
    ar_args.extend(objects.into_iter().map(PathBuf::into_os_string));
    run(&ar, &ar_args);

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static={LIB}");
}

/// `-O` at the level the rest of this build uses, so the reference is
/// not handicapped against the contender by a flag nobody chose.
fn optimisation() -> OsString {
    let level = env::var("OPT_LEVEL").unwrap_or_else(|_| String::from("3"));
    format!("-O{level}").into()
}

/// Compile every translation unit and return the object paths.
fn compile(
    cc: &OsString,
    cflags: &[OsString],
    manifest: &Path,
    source: &Path,
    shim: &Path,
    out: &Path,
) -> Vec<PathBuf> {
    let mut objects = Vec::new();
    for unit in SOURCES {
        let stem = Path::new(unit)
            .file_stem()
            .expect("every source has a file name");
        let object = out.join(stem).with_extension("o");
        let mut args: Vec<OsString> = cflags.to_vec();
        args.push("-I".into());
        args.push(source.as_os_str().into());
        args.push("-I".into());
        args.push(shim.as_os_str().into());
        args.push("-c".into());
        args.push(manifest.join(unit).into_os_string());
        args.push("-o".into());
        args.push(object.as_os_str().into());
        run(cc, &args);
        objects.push(object);
    }
    objects
}
