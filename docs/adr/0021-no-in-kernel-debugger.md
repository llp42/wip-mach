# No in-kernel debugger

Debugging is GDB attached to QEMU's GDB stub, plus the panic line on
the serial console. The kernel has no ddb or kdb: no key sequence into
a debugger and no debugger hooks in drivers. The hardware debug
registers stay only because they are part of the ABI thread state.
`host_reboot` with `RB_DEBUGGER` parks the machine for GDB
(ADR 0018).

## Considered Options

- **Port ddb**: a second debugger, with its own user interface, running
  inside a kernel that has already gone wrong.
- **An in-kernel GDB remote stub over serial**: only bare-metal
  debugging needs it, and it can come with its own ADR if it does.

## Consequences

- On real hardware, the serial panic line is the only debugging aid
  until an ADR adds a stub.
