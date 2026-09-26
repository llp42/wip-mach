# A thread holds at most one lock of a class at a time

There is no multi-lock guard like Zircon's `guard_multiple`, and the
order checker panics when a thread takes a second lock of a class it
already holds. Deadlock between locks of one class then needs no
address-ordering convention, and every class's place in the lock order
is a single node.

GNU Mach holds two locks of one class in only five places, each with a
redesign for the migration:

- shadow-chain walks in `vm_fault_page` and `vm_object_name` (lock
  coupling): one lock per chain of shadow objects, as Zircon's
  `VmCowPages` shares a lock across a hierarchy;
- `thread_halt` and `thread_terminate`, which lock the target and the
  current thread in address order: a halt protocol that holds one thread
  lock at a time;
- `processor_doaction`, moving a processor between two sets: the
  existing lock over all processor sets instead;
- `vm_page_seg_double_lock`, moving pages between two segments: a
  transfer step that holds one segment at a time.

## Consequences

Code that truly needs two objects of one kind at once must find a lock
above both, or restructure the operation. This replaces the checker's
earlier rule, which let two locks of one class nest silently.
