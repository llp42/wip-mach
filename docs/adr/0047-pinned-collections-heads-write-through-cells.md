# Pinned `collections` heads write through `Cell`s

`List`, `SimpleQueue` and `TailQueue` store pointers back into their
own head, so these heads are `!Unpin` and mutate through
`Pin<&mut Self>`. Their methods turn `Pin<&mut Self>` into `&Self` and
write through `Cell`s; they never take `&mut` to a head field, so the
pointers into the head stay valid. `new()` is `const` on every head and
needs no address; `SinglyList` points only at nodes and moves freely.
