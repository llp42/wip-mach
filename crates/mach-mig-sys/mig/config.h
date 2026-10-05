/*
 * The defines the MIG `.defs`/`.srv`/`.cli` preprocessing sees, mirroring
 * `crates/kernel/src/config.rs` and the configuration of the reference build.
 */
#define APIC 1
#define ATX86_64 1
#define CPU_L1_SHIFT 6
#define KERNEL 1
#define MACH_HOST 1
#define MACH_KERNEL 1
#define MACH_KMSG
#define MULTIPROCESSOR 1
#define NCOM 2
#define NCPUS 2
#define PAE 1
#define __ELF__ 1

#define PACKAGE_NAME "WIP Mach"
#define PACKAGE_VERSION "0.1.0"
#define PACKAGE_STRING "WIP Mach 0.1.0"
#define PACKAGE_TARNAME "wip-mach"
#define PACKAGE_BUGREPORT "https://github.com/llp42/wip-mach/issues"
#define PACKAGE_URL ""
