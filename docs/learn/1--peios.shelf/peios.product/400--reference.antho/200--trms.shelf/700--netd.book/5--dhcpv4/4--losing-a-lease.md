---
title: Losing a Lease
description: How a DHCPv4 lease ends — expiry, a NAK, or the client being stopped — what Address.OnExpiry decides, and when a RELEASE is sent.
---

Lease expiry, network loss, and profile changes affect an interface
differently. The configured expiry policy determines whether an expired
address remains installed.

## Lost by the network [*dhcp4-loss.lost]

A lease is **lost** when a Rebinding client reaches the lease's end (§5.2), or
when a NAK arrives while renewing or rebinding (§5.3). The client forgets the
lease and enters Selecting, and netd acts on the interface's
`Address.OnExpiry`:

- **`Drop`** (the default): netd logs `interface <name>: lease lost` and
  forgets the lease. The next reconcile removes the address and the routes
  that came with it. [*dhcp4-loss.drop-removes-the-address]
- **`Keep`**: netd logs `interface <name>: lease lost; keeping the address
  (Address.OnExpiry = Keep)` at warning level and goes on desiring the
  lost lease — its address, gateway, and routes — while the client looks
  for a new one. The kept lease is replaced the moment a new one binds.
  [*dhcp4-loss.keep-holds-the-lease]

With `Keep`, the status reply's `lease` describes the client, not the kept
lease: it disappears with the client's lease, while the address stays on the
interface.

`Keep` lasts while the client lasts. A stop (below) forgets the kept lease as
it would any other.

## Stopped by netd [*dhcp4-loss.stop-releases]

netd stops a client when:

- the interface's outcome changes: another verdict, another profile, or
  any value of its profile edited (§3.3);
- the interface loses carrier (§4.1);
- the profile does not want a client (§5.1).

A client in Bound, Renewing, or Rebinding sends a RELEASE to its server first:
unicast from the lease address (§5.1, §5.6). After a carrier loss that RELEASE
goes out on a link with no carrier, so the server never sees it. The client is
then discarded, and the interface's lease and link-local address are
forgotten, so the next reconcile removes both addresses.

A link that disappears from the kernel takes its client with it and sends
nothing.

## The operator's renew [*dhcp4-loss.operator-renew]

The control request `renew` (§9.2), and so `net renew <interface>`, moves a
client in Bound, Renewing or Rebinding into Renewing at once: a new
transaction id and a unicast REQUEST to the lease's server. The lease is not
released first, and its address stays on the interface throughout. A client
that holds no lease is left as it is, and the request still answers `ok`.
