# Lint policy

The root `Cargo.toml` defines the shared lint rules. Adding or changing
a lint there needs no ADR justification. Crates using those rules
inherit them with `[lints] workspace = true`. Cargo cannot merge
workspace and package lint tables, so a crate with additional rules
keeps a complete table in its own `Cargo.toml`.

A local exception is `#[expect(lint, reason = "…")]`, never
`#[allow]`: every crate denies `allow_attributes` and
`allow_attributes_without_reason`. Test-only relaxations — `unwrap`,
`expect`, indexing, panics in tests — live in the crate's
`clippy.toml`, never in the library. A crate-wide exception needs the
same reason a local one does; "the C did it this way" is not one
(ADR 0027).

A crate that denies `restriction`, as `collections` does, lists the few
`restriction` lints it allows in its `Cargo.toml`, with their reasons
recorded here. Every reason is one of three kinds: the lint contradicts
another lint (`implicit_return`, one of each semicolon or visibility
pair), it goes against plain Rust idiom (`?`, `pub use`, `mod.rs`), or
it goes against the comment rules of ADR 0025 (a SAFETY comment inside
an `unsafe fn`, docs that respell a private name). A new allowance
needs a reason of the same kind; everything else is fixed in the code.

## Manifest exceptions

`collections` allows these lints:

| Lint | Reason |
| --- | --- |
| `blanket_clippy_restriction_lints` | The restriction group is intentional; conflicting rules are disabled individually. |
| `implicit_return` | Conflicts with `needless_return`. |
| `semicolon_inside_block` | Conflicts with `semicolon_outside_block`. |
| `mod_module_files` | Conflicts with `self_named_module_files`; each shape uses `mod.rs`. |
| `missing_trait_methods` | Rust traits provide default methods so implementations can omit them. |
| `arbitrary_source_item_ordering` | Items follow their API relationships rather than alphabetical order. |
| `question_mark_used` | `?` is the idiomatic early return for `Option` and `Result`. |
| `pub_use` | Modules re-export their public API. |
| `inline_modules` | Unit tests live beside the code they exercise. |
| `undocumented_unsafe_blocks` | An unsafe function's contract can cover its blocks without repeating a comment. |
| `multiple_unsafe_ops_per_block` | Operations sharing one safety precondition can share one block. |
| `missing_docs_in_private_items` | Private names need documentation only for facts the code cannot express. |
| `redundant_pub_crate` | Conflicts with rustc's `unreachable_pub`. |
| `pub_with_shorthand` | Conflicts with `pub_without_shorthand`; use `pub(crate)`. |

`elf-load`, `kmem` and `lock` also allow `redundant_pub_crate` for
the same reason. `elf-load` allows `struct_field_names` because its
fields follow the ELF header's `e_*` and `p_*` names.

## Considered Options

- **`#[allow]` with a comment**: it outlives its reason silently,
  while an `#[expect]` that stops firing fails the build.
- **Requiring every crate to inherit one table**: it cannot vary per
  crate, and the crates differ on purpose.

## Consequences

- Clean means zero warnings on every clippy run the gates list
  (ADR 0024).
