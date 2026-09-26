# `collections` adapter macros bind the link field uncast

Each shape's `adapter!` macro binds the link field without a cast, so
the field must be exactly that shape's `Link` and any other type fails
to compile. `Adapter` is an `unsafe trait`: a hand-written adapter
promises the same field-to-node mapping the macro proves.
