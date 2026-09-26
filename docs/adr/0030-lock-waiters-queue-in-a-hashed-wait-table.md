# Lock waiters queue in a hashed wait table the platform supplies

Parked threads queue in a wait table hashed by lock address, not in a list
inside each lock, as parking_lot and FreeBSD's sleepqueues and turnstiles
do. Every lock stays one word, and Mutex, RwLock and Condvar share one
queueing mechanism. The platform supplies the table instead of the lock
crate owning a `static`, because loom needs every atomic created inside
each model run.
