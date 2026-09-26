# `collections` `Debug` prints link pointers only

Heads, cursors and iterators implement `Debug` by hand and print their
link pointers, never the nodes, so no `Node: Debug` bound appears on
any public type.
