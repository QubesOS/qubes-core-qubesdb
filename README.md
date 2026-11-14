# QubesDB

QubesDB is part of [Qubes OS](https://www.qubes-os.org). It is a small
hierarchical key/value database used to hold configuration and state, and to
exchange it between dom0 and a VM.

Each VM has its own database, held by two daemons: one inside the VM, and one
in dom0 that runs only for that VM. Each daemon serves local clients over a
socket, and the pair keeps in sync over an inter-VM channel.

This repository contains the daemon, the C client library and its header, the
`qubesdb-cmd` command-line tool, and the Python bindings.

For how Qubes OS works and how its components fit together, see the
[Qubes OS documentation](https://www.qubes-os.org/doc/).
