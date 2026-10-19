---
title: The Socket and Its Object
description: netd's control socket — its path and descriptors, the control object and its default descriptor, the access rights and their generic mapping, and how each connection is checked.
---

The control socket accepts local requests to inspect or change network
state. A separate security object governs access to those operations.

## The socket [*control.socket-path-and-descriptor]

netd listens on `/run/netd/control.sock`, a `SOCK_STREAM` Unix socket. At
startup it:

1. creates `/run/netd` if it is missing, sets its mode to `0755`, and
   gives it the descriptor below;
2. removes a socket file left by a previous run, logging `removed a stale
   /run/netd/control.sock`;
3. binds, sets the socket file's mode to `0666`, and gives it the same
   descriptor.

The descriptor on both: owner and group SYSTEM, and a DACL allowing SYSTEM
`GENERIC_ALL` and Everyone `GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE`.
peinit creates `/run` SYSTEM-only and inheritable, so without it nobody else
could reach the socket. Everyone can connect; the control object decides what
each connection can do. A failure to set it is logged as an error and netd
carries on.

## The control object [*control.object-default-descriptor]

Every request is checked against the **control object**, a security descriptor
netd holds in memory. It is `Machine\System\Network ControlSecurity`, a
self-relative descriptor in a `REG_BINARY` value, when that is set and valid.
When it is not valid, netd logs
`ControlSecurity is not a valid descriptor (…); using the default`.

The compiled default: owner and group SYSTEM, and a DACL of:

| Trustee | Rights |
|---|---|
| SYSTEM | `NETWORK_ALL_ACCESS` |
| Administrators | `NETWORK_ALL_ACCESS` |
| Everyone | `NETWORK_QUERY`, `READ_CONTROL` |

The object is rebuilt whenever the configuration changes (§2.3), so a
written `ControlSecurity` applies to the next connection.
[*control.object-follows-control-security]

## Rights [*control.rights-and-mapping]

| Right | Value |
|---|---|
| `NETWORK_QUERY` | `0x00000001` |
| `NETWORK_CONTROL` | `0x00000002` |
| `NETWORK_ALL_ACCESS` | `0x000F0003`: both, plus the standard rights |

The generic mapping:

| Generic right | Maps to |
|---|---|
| read | `NETWORK_QUERY`, `READ_CONTROL` |
| write | `NETWORK_CONTROL`, `READ_CONTROL` |
| execute | `NETWORK_QUERY` |
| all | `NETWORK_ALL_ACCESS` |

## The check [*control.access-check-on-peer-token]

For each request, netd opens the connecting peer's token through KACS and runs
a real access check of the request's right (§9.2) against the control object.
It never looks at `SO_PEERCRED`, so a deny-only group or a filtered token is
judged as the kernel would judge it anywhere else. A peer whose token cannot
be opened is denied, and so is one whose token's user cannot be read, since a
change made for it is recorded under that user (§8.4).

A denied request is answered `{ok: false, error: "access denied"}`, and
nothing else happens.

## Nonblocking client I/O [*control.serial-and-blocking]

The control socket is served on netd's one thread (§2.2). Accepted connections
are nonblocking and polled alongside network and registry inputs. An idle
client, partial request, or client that does not read its reply does not hold
the loop in a socket read or write.

At most 64 requests or replies are pending at once. While full, netd stops
polling the listener until a slot becomes free; connections still waiting in
the kernel backlog have not been accepted. Each iteration accepts at most 16
connections and reads or writes at most 4 096 bytes per ready pending
connection. The 65 536-byte message ceiling is checked from the header before
reading a request payload (§9.2).

A request must complete within two seconds of acceptance. A normal reply must
be written within two seconds of being queued. Partial progress does not
extend either deadline. Expiry closes the connection without a timeout reply.
These deadlines participate in the same poll timeout as network-client timers.
Completed subscriptions leave this pending-client set and use the existing
nonblocking snapshot publisher (§8.3).
