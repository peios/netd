# netd

netd manages Peios network interfaces, addresses, routes, and resolver facts.
The repository also provides the `net` command, `libnetd.so.1`, and the safe
Rust `netd-client` wrapper.

- [Build, test, and package](docs/building.md)
- [Learn documentation](docs/learn/1--peios.shelf/peios.product/400--reference.antho/200--trms.shelf/700--netd.book)
- [Command and library manuals](docs/man)
- [Registry reference](docs/netd.regman) and [event reference](docs/netd.evman)

`netd-core` contains internal policy and wire types. `dhcp4`, `dhcp6`, and
`ndp` contain pure protocol state machines. The daemon owns operating-system
integration. External applications use the shared library or its Rust wrapper.

Development builds run on x86-64 Linux. Running the daemon requires Peios
kernel interfaces and libpeios; a successful host build does not qualify
network behavior on a Peios system.

Peios coding and documentation standards live in Panorama's PSC product.
Imported kernel and package-writer snapshots keep their upstream style and
recorded provenance. Maintained code and local build definitions follow PSC.
