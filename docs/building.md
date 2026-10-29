# Building netd

Use pekit to build the network daemon, its operator command, and its C
client library, and to run their tests. Pekit builds each crate on its own,
so a change rebuilds only the crates it reaches. The supported development
host is x86-64 Linux.

## Before you start

You need pekit and Git. Everything else is pinned and fetched by pekit on
the first build: the Bootlin C toolchain, Rust 1.98.1 with Clippy, Python
3.14, libclang, and the crates `Cargo.lock` selects. The first build needs
network access; later builds find what they need in pekit's store, and every
step runs without network access in a sandbox that holds only its declared
inputs.

The build files use the gcslib libraries named in `workspace.gcsl` and the
build files, and the libraries of peios-rs and the Peios SDK. `pekit lock`
pins their commits in `pekit.lock`.

## Build

```sh
pekit build netd net libnetd
```

| Target | Output |
|---|---|
| `netd` | Network daemon |
| `net` | Operator command, a client of netd's control socket |
| `libnetd` | Public C client library, `libnetd.so.1` by its shared object name (SONAME) |

Pekit prints where each output is, under `pekit-out/<target>/`. The
programs load `libpeios.so.0` by its SONAME, and `net` loads `libnetd.so.1`.
They carry no runtime search path, so running them needs both libraries
installed. Do not run the daemon on the development host as part of a build
check.

Programs are built with the workspace's release profile: thin link-time
optimization, one code-generation unit, full debug information, and
aborting panics.

## Test

```sh
pekit test
```

Each member's unit and integration tests are a test of their own, named
after the member: `netd_core`, `dhcp4`, and so on. `netd_core` tests that
crate with its `policy` feature, as netd and libnetd build it. Further tests
check what the C client promises, and the whole workspace's documentation
and lints:

| Test | Check |
|---|---|
| `abi` | A C program that includes the public header, links libnetd, and calls it |
| `exports` | libnetd exports exactly the symbols in `libnetd/exports.txt`, and its header is valid C++ |
| `doctests` | Each member's documentation tests, as `cargo test --doc` runs them |
| `clippy` | Clippy's checks of every target of every member, with every warning denied |
| `api_docs` | The `netd-client` documentation, as `cargo doc` makes it, with every warning denied |

The kernel's crates that netd vendors, `pnp-core` and `peios-uapi`, are
workspace members, but `doctests` and `clippy` leave them to the kernel.

A test whose inputs did not change is found in the store and not run
again. The checks cover state machines, registry-read failure handling,
socket framing, C callers, and the Rust shared-library wrapper. They do not
configure host network devices. VM probes under `tests/vm/` need a
separately supplied Peios image; run them in a disposable guest. They
collect diagnostic reports and are not an automated qualification suite.

For the full contributor check, install the pinned PSC tools into a
directory outside the repository, then run the shared entry point:

```sh
python3 tools/prepare-style-tools.py "$HOME/.cache/netd-style"
export PEIOS_STYLE_BIN="$HOME/.cache/netd-style/bin"
tools/check
```

`tools/check` checks owned source formatting and lint with Ruff,
ShellCheck, shfmt, clang-format, Prettier, and rustfmt. It then checks the
kernel snapshot and the generated interfaces, and runs `pekit test`. The
style checks use the host's Rust 1.98.1 formatter through rustup. The tool
versions and hashes are recorded in `tools/style-tools.lock.json`. Tool
setup needs Node.js 22, Python, and `venv`. GitHub's workflow runs the
style checks alone; builds and tests run with pekit.

## How the build is planned

`build.gcsl` plans the Cargo workspace with the gcslib rust library's
`workspace`: Cargo works out each member's build, unit by unit, and pekit
compiles each unit as a step. Planning reads the manifests, `Cargo.lock`,
and which files exist, never the sources, so editing a source plans nothing
again. Each member's crates are compiled with the lints in the workspace's
`[lints]` table, as Cargo compiles them.

Keep Rust dependency versions in the Cargo manifests and `Cargo.lock`, and
update the lockfile deliberately with Cargo. A package that needs more than
its manifest says is given it in `build.gcsl`:

- `peios-sys` generates its bindings from the SDK's headers with bindgen and
  links libpeios, so it, and every crate that depends on it, is given what
  peios-rs's library says it needs, `crate_settings()`: libpeios and its
  headers;
- `pnp-core` and `peios-uapi` read the kernel's sources in `vendor/kernel/`;
- `netd-client` links libnetd, so it, and `net`, are given the library
  pekit builds.

libpeios and its headers are built from the Peios SDK's own files, through
the SDK's GCSL library, which peios-rs's library imports. The commits
`pekit.lock` pins say which SDK and which peios-rs; the rust library fails a
build whose `Cargo.lock` takes peios-rs's crates at another commit than
`pekit.lock` pins its library at, so the crates and the settings they are
built with always agree. authd and eventd take the same peios-rs commit.

## Building against netd

netd is a GCSL library as well as a workspace. A workspace whose crates
depend on `netd-client` gives it libnetd, which it links, and gives its
programs libnetd, and the libpeios it loads, when they run:

```text
import "github.com/peios/netd"
import "github.com/peios/peios-rs" as peios_rs

rust.workspace(..., crates = [...peios_rs.crate_settings(), ...netd.crate_settings()])
rust.run_test(test, given = [...peios_rs.runtime(), ...netd.runtime()], env = netd.runtime_env())
```

`pekit lock` pins netd's commit in the workspace's `pekit.lock`. The rust
library fails a build whose `Cargo.lock` takes netd's crates at another
commit than that, so the crate and the libnetd it links always agree.

## Not built with pekit yet

Packages and builds with the native Peios toolchain, which hardens
programs with control-flow enforcement technology (CET), are not yet built
with pekit. The package definitions and native build settings from the
Bazel build are kept outside this repository until they are.

## Generated interfaces

`tools/netd-abi.json` defines the shared C and Rust layouts. Run
`tools/generate-netd-abi.py` after changing it; `--check` verifies the
outputs without rewriting them. ABI changes need review, even if generation
and compilation succeed.

The exact kernel snapshot is recorded in `vendor/kernel/ORIGIN.json`.
`tools/update-kernel-inputs.py check` verifies it. Imported sources keep
upstream formatting.

## Documentation

Use a Trail version supporting merges at every tree level:

```sh
tools/check-docs
tools/check-docs --context ../learn
```

Component checks permit only the reviewed external-link diagnostics recorded
in `docs/external-links.json`. The full publication check verifies links in
the merged Learn tree. `docs/migration-source-map.json` records the original
staging paths and hashes; cross-component specifications remain with their
own documentation trees.
