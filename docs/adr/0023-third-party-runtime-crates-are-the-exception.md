# Third-party runtime crates are the exception

In-house crates are preferred. A third-party crate linked into the
kernel image is allowed only when it is `no_std`, pinned to an exact
version (`=x.y.z`), audited and licence-compatible. Audited means:

- it is listed below, with the reason it is worth its supply chain;
- adding one amends this ADR;
- moving its pin is a change that reviews the upstream diff.

`cargo deny` checks licences and exact pins in CI. Build and dev
dependencies such as `criterion` and `loom` never reach the image and
need only an exact pin and a compatible licence.

Allowed runtime crates: none.

## Considered Options

- **Any `no_std` crate**: the kernel image takes on every upstream's
  supply chain, one convenience at a time.
- **`cargo vet`**: a second audit store beside this list, for a list
  that is empty or close to it.

## Consequences

- A crate that needs `alloc` cannot be used (ADR 0017).
- Locks come from `lock` and intrusive lists from `collections`.
