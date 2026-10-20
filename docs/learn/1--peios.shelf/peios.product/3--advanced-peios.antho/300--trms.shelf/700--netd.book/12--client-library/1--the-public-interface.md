---
title: The Public Interface
description: Shared-library operations, ownership, timeouts, and Rust wrappers.
---

`libnetd.so.1` exposes daemon access and configuration validation through a C
application binary interface (ABI). The `netd-client` Rust crate wraps that
same shared library. It does not embed a second implementation.

## Daemon operations

The library reads status, requests lease renewal or reconciliation, and
subscribes to resolver snapshots. Each ordinary operation opens its own Unix
socket connection. The default path is `/run/netd/control.sock`; callers can
select another filesystem socket.

A positive timeout in milliseconds bounds the entire connection, send, and
receive exchange. A full listen queue can return `EAGAIN` before the deadline.
A failed exchange does not prove that a command was not applied. The library
does not replay commands or reconnect subscriptions automatically.

The library preserves the daemon's authorization checks. A successful
connection alone does not grant permission to query or change network state.

## Ownership and errors

Each operation returns an owned result, including failures. The caller checks
`peios_netd_result_error` before reading a result and frees it exactly once
with `peios_netd_result_free`. Error codes are POSIX values; diagnostics are
human-readable text, not stable identifiers. `peios_netd_result_error`
returns the stored code without setting thread-local `errno`.

Returned strings and arrays are borrowed from the result. Strings contain
UTF-8 bytes with explicit lengths and do not include a terminating NUL. A
result owns copies of its input, so its views do not depend on caller buffers.
Immutable results support concurrent readers; freeing a result must wait for
all readers to finish. Input and output pointer requirements are documented
in `<peios/netd.h>` and `libnetd(3)`.

A subscription has independent ownership and must be freed separately. Calls
and destruction on one subscription must not overlap. A receive timeout
retains partial framing for the next call. Other receive errors close the
connection and leave the subscription unusable.

## Configuration validation

Hostname checking returns the normalized hostname or an error. Profile
resolution and policy construction accept neutral registry trees and perform
no registry writes. Policy judgment accepts interface facts and reports the
outcome using the same policy implementation as the daemon.

The public input boundary accepts at most 128 key levels, 65,536 total keys,
values, and list items, and 4 MiB of text across both trees. Each fact set has
a separate 4 MiB text limit. These limits bound library input handling; the
daemon's registry reader and the policy parser impose their own limits.

Profile names compare without ASCII case distinctions. Invalid actions return
validation errors, including malformed non-ASCII text. Disabled profiles
remain visible in resolved results so configuration editors can inspect them.

## Rust access

`Client::system` selects the installed socket with an explicit `Duration`.
`status`, `renew`, `reconcile`, and `subscribe` use the shared library. The
wrapper returns owned Rust values and releases C results through `Drop`.

`check_hostname` validates a hostname. `Policy::build`, `resolve_profiles`,
and `judge` expose configuration checks. Policy and subscription handles
remain bound to their owning thread; the wrapper does not declare them
`Send` or `Sync`.

The installed `libnetd-devel` package supplies the C development interface.
Rust consumers select a matching `netd-client` source revision and link the
installed library. The internal `netd-core` crate is not a replacement for
the public shared-library boundary.
