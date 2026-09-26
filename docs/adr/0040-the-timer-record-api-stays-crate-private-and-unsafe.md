# The timer record API stays crate-private and unsafe

`clock`'s `Record` and `HashedWheel::{start, stop, is_idle}` remain
`pub(crate)` and `unsafe`. They are the primitives `Callout` (ADR 0039)
is built from; making them public again would let callers free a live
record or arm one that can move. A record is reached by address, so it
carries `PhantomPinned`, and every field is written under the lock of
the wheel it is on.

Memory the kernel frees without running `Drop` (a zone allocation) may
still hold a callout: the code that pins it there, with
`Pin::new_unchecked`, promises to drop it before the memory is reused.
That is the only remaining `unsafe` the public story leaves to a
caller.

## Considered Options

- **A public `unsafe` record API** beside `Callout`: two surfaces for
  one job, and the safe one is no longer the only path.
- **`Record` in the public type of `Callout`**: exposes the link and
  state cells the wheel owns the right to mutate.
