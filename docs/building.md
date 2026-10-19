# Building netd

Build on x86-64 Linux with a C/C++ compiler, linker, Python 3.11 or later,
libclang, and network access for initial dependency acquisition. The launcher
verifies Bazel 8.4.2 against its recorded digest. `MODULE.bazel` pins Rust
1.98.1 and the build rules; `Cargo.lock` pins Rust dependencies.

## Development SDK

Set `PEIOS_SDK` to an absolute SDK directory containing `include/peios.h`,
`include/peios/`, `include/pkm/`, and `lib/libpeios.so.0`. The build imports
those inputs explicitly. CI builds the published libpeios revision recorded
in `.github/workflows/check.yml` and uses this repository's kernel snapshot.

For that pinned libpeios source layout, prepare a fresh development SDK:

```sh
tools/prepare-dev-sdk /path/to/libpeios vendor/kernel/include/uapi /tmp/netd-sdk
export PEIOS_SDK=/tmp/netd-sdk
```

This helper builds the selected SDK source with Cargo. netd's production build
and packaging interface is Bazel. A Debian SDK supports development checks;
it does not provide a native Peios runtime.

## Build and test

```sh
./bazel test //...
./bazel build //netd //net //libnetd //:packages
```

The checks cover state machines, registry-read failure handling, socket
framing, C callers, the Rust shared-library wrapper, and the package store.
They do not configure host network devices. VM probes under `tests/vm/`
require a separately supplied Peios image; run them in a disposable guest. They collect diagnostic reports and do not
constitute an automated pass/fail qualification suite.

The complete package store is `bazel-bin/packages.store`. It contains
canonical PPK manifests and content-addressed compressed blobs for:

- `netd`, `net`, and `libnetd`
- `libnetd-devel`, with C headers, the linker symlink, pkg-config metadata,
  and the library manual
- Separate debug information for each runtime package
- Shared source and debug-source packages

All nine packages use version `0.1.8-1`. The writer verifies decompressed blob
hashes and manifest references. Development packages are unsigned and their
provenance records that they are not release-ready. Native builds retain
that publication distinction; signing and release approval are separate.

## Style and generated interfaces

Prepare pinned tools outside the repository, then run all host checks:

```sh
python3 tools/prepare-style-tools.py /tmp/netd-style
PEIOS_STYLE_BIN=/tmp/netd-style/bin tools/check
```

Tool setup needs Rust 1.98.1 with rustfmt and Clippy, Node.js 22, Python, and `venv`.
`tools/netd-abi.json` defines the shared C and Rust layouts. Run
`tools/generate-netd-abi.py` after changing it; `--check` verifies the outputs
without rewriting them. ABI changes require review, even if generation and
compilation succeed.

The exact kernel snapshot is recorded in `vendor/kernel/ORIGIN.json`.
`tools/update-kernel-inputs.py check` verifies it. Imported sources retain
upstream formatting; the local Bazel definitions remain maintained here.

## Native Peios builds

`--config=peios` selects the installed patched Peios Rust compiler and hardened
standard library. Set `PEIOS_RUSTC` when it is not `/usr/bin/rustc`. Supply a
native Peios SDK through `PEIOS_SDK`; a Debian shared library is not suitable.

Acquire dependencies on a networked development host:

```sh
tools/offline-build acquire /tmp/netd-inputs
```

Copy the source and snapshot into an isolated native Peios userspace with its
compiler, compatible C/C++ tools, linker, Python, and Bazel host requirements.
Run there:

```sh
tools/offline-build test /tmp/netd-inputs /tmp/netd-work
```

The helper freezes external repositories and disables repository downloads.
The caller supplies isolation and blocks network access. Native package checks
inspect CET, RELR, RELRO, stack permissions, dependencies, and split debug
information. Passing those checks does not replace VM network qualification.

## Documentation

Use the Trail revision pinned in CI:

```sh
tools/check-docs
tools/check-docs --context ../panorama/docs
```

Component checks permit only the reviewed external-link diagnostics recorded
in `docs/external-links.json`. The full publication check verifies links in
the merged Learn tree. `docs/migration-source-map.json` records the original
staging paths and hashes; cross-component specifications remain with their
own documentation trees.
