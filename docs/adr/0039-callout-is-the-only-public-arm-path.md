# `Callout` is the only public arm path

A `clock` `Callout` owns its record, is bound to one wheel for its
whole life by a `'w` borrow, and arms only when pinned. Its `Drop` runs
`cancel`: stop, then wait until the record is idle, so the memory
cannot be reused while another CPU is inside the action. The safe
surface is the only public way to arm a wheel; the raw record stays
crate-private (ADR 0040). Cost over the raw calls is none on start and
stop and 0.1–0.3 ns per expiry.

A callout must not be dropped or cancelled from its own action, or from
an interrupt taken during the `advance` running it: the wait never
ends. `start` requires `Callout: Sync`, since the action may run on
another CPU. A callout cannot move between wheels.

## Considered Options

- **Public `Record` + `unsafe` arming**: every caller re-encodes the
  pin, lifetime and drop-wait contract; one mistake frees a live
  record.
- **`Drop` that only stops**: returns while the action still runs, so
  the owner may free memory the action reads.
