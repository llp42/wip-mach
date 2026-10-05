// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Generates the MIG glue from `mig/` and links it into every dependent
//! image.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Input {
    name: &'static str,
    ext: &'static str,
    dir: &'static str,
    server: bool,
}

const INPUTS: &[Input] = &[
    Input {
        name: "device",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "device_pager",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "experimental",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "gnumach",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "mach",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "mach4",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "mach_debug",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "mach_host",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "mach_i386",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "mach_port",
        ext: "srv",
        dir: "srv",
        server: true,
    },
    Input {
        name: "device_reply",
        ext: "cli",
        dir: "cli",
        server: false,
    },
    Input {
        name: "memory_object_default",
        ext: "cli",
        dir: "cli",
        server: false,
    },
    Input {
        name: "memory_object_reply",
        ext: "cli",
        dir: "cli",
        server: false,
    },
    Input {
        name: "memory_object_user",
        ext: "cli",
        dir: "cli",
        server: false,
    },
    Input {
        name: "task_notify",
        ext: "cli",
        dir: "cli",
        server: false,
    },
];

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

fn run_with_stdin(program: &OsString, args: &[OsString], stdin: &Path) {
    let file = std::fs::File::open(stdin)
        .unwrap_or_else(|e| panic!("cannot open {}: {e}", stdin.display()));
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::from(file))
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
    let mig = tool("MIG", "x86_64-gnu-mig");
    let ar = tool("AR", "ar");

    for program in [&mig, &cc] {
        assert!(
            probe(program),
            "{} is missing; the MIG glue needs it",
            program.to_string_lossy()
        );
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=mig");

    let defs = manifest.join("mig/defs");
    let shim = manifest.join("mig/include");
    let config = manifest.join("mig/config.h");

    let cflags: Vec<OsString> = [
        "-std=gnu11",
        "-O2",
        "-Wall",
        "-Werror=implicit-function-declaration",
        "-mno-red-zone",
        "-mcmodel=kernel",
        "-mno-3dnow",
        "-mno-mmx",
        "-mno-sse",
        "-mno-sse2",
        "-ffreestanding",
        "-nostdlib",
        "-fno-stack-protector",
        "-fno-strict-aliasing",
        "-no-pie",
        "-fno-PIE",
        "-fno-pic",
        "-DRDXTREE_KEY_32",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();

    let mut generated = Vec::new();
    for input in INPUTS {
        generated
            .push(generate(&mig, &cc, input, &manifest, &defs, &config, &out));
    }

    let objects = compile(&cc, &cflags, &config, &shim, &out, generated);

    let lib = out.join("libmach_mig.a");
    let mut ar_args: Vec<OsString> =
        vec!["crs".into(), lib.as_os_str().into()];
    ar_args.extend(objects.into_iter().map(PathBuf::into_os_string));
    run(&ar, &ar_args);

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static:+whole-archive=mach_mig");
}

/// Preprocess one server or client stub input and run MIG on it, returning the
/// generated C file and the object path it compiles to.
fn generate(
    mig: &OsString,
    cc: &OsString,
    input: &Input,
    manifest: &Path,
    defs: &Path,
    config: &Path,
    out: &Path,
) -> (PathBuf, PathBuf) {
    let stem = format!("{}.{}", input.name, input.ext);
    let src = manifest.join("mig").join(input.dir).join(&stem);
    let pre = out.join(format!("{stem}.i"));
    let c = out.join(format!("{stem}.c"));
    let h = out.join(format!("{stem}.h"));
    let list = out.join(format!("{stem}.msgids"));

    run(
        cc,
        &[
            OsString::from("-E"),
            OsString::from("-x"),
            OsString::from("c"),
            OsString::from("-I"),
            defs.as_os_str().into(),
            OsString::from("-imacros"),
            config.as_os_str().into(),
            OsString::from("-D_START_MAP=0x1000000"),
            OsString::from("-o"),
            pre.as_os_str().into(),
            src.as_os_str().into(),
        ],
    );

    let mut args: Vec<OsString> = ["-n", "-cc", "cat", "-", "/dev/null"]
        .into_iter()
        .map(OsString::from)
        .collect();
    if input.server {
        args.push("-sheader".into());
        args.push(h.into());
        args.push("-server".into());
    } else {
        args.push("-header".into());
        args.push(h.into());
        args.push("-user".into());
    }
    args.push(c.as_os_str().into());
    args.push("-list".into());
    args.push(list.into());
    run_with_stdin(mig, &args, &pre);

    (c, out.join(format!("{stem}.o")))
}

/// Compile every generated C file with `cc` and return the object paths.
fn compile(
    cc: &OsString,
    cflags: &[OsString],
    config: &Path,
    shim: &Path,
    out: &Path,
    generated: Vec<(PathBuf, PathBuf)>,
) -> Vec<PathBuf> {
    let mut objects = Vec::new();
    for (c, obj) in generated {
        let mut command: Vec<OsString> = cflags.to_vec();
        command.push("-imacros".into());
        command.push(config.as_os_str().into());
        command.push("-I".into());
        command.push(shim.as_os_str().into());
        command.push("-I".into());
        command.push(out.as_os_str().into());
        command.push("-c".into());
        command.push("-o".into());
        command.push(obj.as_os_str().into());
        command.push(c.as_os_str().into());
        run(cc, &command);

        objects.push(obj);
    }
    objects
}
