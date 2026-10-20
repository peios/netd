---
title: Identity and Carrier
description: How netd classifies a link, derives its stable interface id, bus path and driver, and what appearing, disappearing and losing carrier do.
---

An interface has a stable Peios identity as well as its kernel name and
index. Carrier changes determine when its network clients start and stop.

## Kind [*ifid.kind]

netd classifies each kernel link once per dump:

| Link | `Interface.Kind` |
|---|---|
| the loopback flag set | `loopback` |
| link type Ethernet, with `/sys/class/net/<name>/wireless` or `/sys/class/net/<name>/phy80211` present | `wireless` |
| link type Ethernet otherwise | `wired` |
| any other link type | `other` |

A bridge, a veth, or a `TAP` device has link type Ethernet and is `wired`.

## Bus path and driver [*ifid.path-and-driver]

The **bus path** comes from sysfs. netd resolves
`/sys/class/net/<name>/device` and walks up from it to the nearest ancestor
whose name is a PCI address (`dddd:bb:dd.f`), and names it `pci-<address>`. A
device with no PCI ancestor is named by the device's own directory name. A
link with no `device` (a virtual device) has no bus path. A virtio NIC sits
one level below its PCI function, so it is named by the function.

The **driver** is the name the `device/driver` link points at (`virtio_net`,
for example), and empty when there is none.

Both are read once, when netd first sees the link.

## The interface id [*ifid.derivation]

The interface id is a SHA-1 digest of the bytes `peios-netd-ifid|`, then the
bus path if there is one, then `|`, then the six MAC bytes — or, for a link
with no 6-byte hardware address, its name. The first 16 bytes of the digest
are stamped as a version 5, RFC 4122 variant UUID and written in lower-case
hyphenated form.

So the same card in the same slot has the same id on every boot, however
the kernel names it, and a renamed link keeps its id. A virtual device has
no bus path, so its id follows its MAC alone.
[*ifid.stable-across-renames-and-boots]

The id is the key of the interface's record under `Interfaces\` (§8.1), the
`Interface.Id` fact, the key of the RFC 7217 address derivation (§6.2), and
the basis of its DHCP IAID (§5.7).

## Appearing and disappearing [*ifid.appear-disappear]

When netd first sees a link, it reads the link's identity, logs
`interface <name> (<path>) is <id>`, and, unless it is the loopback, writes
`accept_ra = 0` for it (§6.1).

When a link disappears from the kernel's dump, netd drops it and everything it
held: its clients, lease, network, and judgment. Nothing is sent on the wire.
Its record under `Interfaces\` stays.

## Carrier [*ifid.carrier-loss]

netd counts an interface as having carrier when it is administratively up
**and** the kernel reports `IFF_LOWER_UP`. When an interface that had carrier
loses it, netd logs `interface <name>: carrier lost` and:

- stops its DHCPv4 client: a RELEASE is sent if a lease was held, and the
  lease and any link-local address are forgotten (§5.4);
- stops router discovery and DHCPv6;
- forgets the network identified on it (§7.1), so `Status Network` is
  cleared and the `Network.*` facts go absent, for netd's own judgment
  and the kernel's packet layers alike.

The next reconcile then removes the leased and autoconfigured addresses and
the routes that depended on them, because nothing desires them any more.
Static addresses stay. [*ifid.carrier-loss-removes-offered-config]

When carrier returns, the pass starts the clients again from scratch (§5.1,
§6.1), and the DHCPv4 client asks first for the address the network last gave
(§5.7).
