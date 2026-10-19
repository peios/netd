# Fuzzing netd Protocols

The five libFuzzer targets in `fuzz/` exercise DHCPv4 decoding, DHCPv4 client
operations, IPv6 advertisement decoding, router-discovery engine operations,
and DHCPv6 information-client operations. They use in-memory inputs and do
not configure network interfaces.

With nightly Rust and cargo-fuzz installed, run a campaign from the repository
root:

```sh
cargo +nightly fuzz run dhcp4_decode
cargo +nightly fuzz run client_ops
cargo +nightly fuzz run ndp_decode
cargo +nightly fuzz run ndp_engine_ops
cargo +nightly fuzz run dhcp6_client_ops
```

Corpora and failure artifacts stay under `fuzz/corpus/` and `fuzz/artifacts/`.
Preserve a failing input before reducing it, then add a regression test for
its invariant. A campaign does not replace the deterministic tests.

Bazel's ordinary DHCPv4 and NDP test targets include deterministic generated
inputs. Set `DHCP_FUZZ_ITERS` or `NDP_FUZZ_ITERS` through `--test_env` to increase
their counts. These checks exercise decoder bounds, valid lease shapes, and
state-machine behavior under arbitrary messages and monotonic time changes.
