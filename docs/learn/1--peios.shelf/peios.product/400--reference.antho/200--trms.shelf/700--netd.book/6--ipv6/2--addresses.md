---
title: Addresses
description: Stateless address autoconfiguration as netd does it — which prefixes form addresses, the stable-privacy derivation and its secret, lifetimes and the two-hour rule, deprecation, and temporary addresses.
---

netd derives stable and temporary IPv6 addresses from accepted router
advertisements. Prefix lifetimes control when those addresses are preferred,
deprecated, and removed.

## Which prefixes form addresses [*slaac.prefix-acceptance]

A prefix information option forms addresses only when its A flag is set, its
prefix length is exactly 64, and its preferred lifetime does not exceed its
valid lifetime. Any other prefix option is ignored whole. A prefix with only
the L flag gets no address, and no on-link route, because the kernel's RA
handling is off.

A prefix seen for the first time is taken only with a valid lifetime above
zero.

## The stable address [*slaac.stable-privacy-derivation]

Each accepted prefix gets one stable address (RFC 7217): the prefix's first 64
bits, followed by the first 8 bytes of a SHA-1 digest of:

1. the bytes `peios-ndp-stable-iid|`;
2. the machine's 32-byte secret;
3. the prefix's first 8 bytes;
4. the interface id's text;
5. a one-byte counter, starting at 0.

When the resulting interface identifier is reserved (RFC 5453: all zeros,
`0200:5eff:fe00::/40`, or `fdff:ffff:ffff:ff80` to `fdff:ffff:ffff:ffff`), the
counter is incremented and the digest taken again, up to 8 times.

So the same machine on the same network has the same address on every
boot, a different network sees an unrelated address, and no MAC address
ever appears in it. The address is a function of the interface id, so a
kernel rename does not change it either.
[*slaac.same-machine-same-network-same-address]

### The secret [*slaac.secret]

The 32-byte secret is read from `/var/state/netd/secret` the first time an
interface starts router discovery. When the file does not hold exactly 32
bytes, a new secret is drawn from `/dev/urandom` and written there; a failure
to write is logged and the new secret used for the rest of the process's life.
If opening or reading `/dev/urandom` fails, netd logs the failure and skips
IPv6 autoconfiguration for that attempt. It does not use a zero-filled secret.
IPv4 continues independently.

Losing the stored secret changes the derived addresses on the next start.

## Lifetimes [*slaac.lifetimes]

A lifetime of `0xFFFFFFFF` is forever. Others count from the moment the
advertisement arrived.

When an advertisement updates a prefix already held:

- the on-link flag and the preferred lifetime are taken as advertised;
- the valid lifetime uses the two-hour rule from
  [RFC 4862
  §5.5.3(e)](https://www.rfc-editor.org/rfc/rfc4862.html#section-5.5.3),
  including prefixes whose previous lifetime was infinite:

| Advertised valid lifetime | Remaining valid lifetime | Result |
|---|---|---|
| above two hours, or above what remains | any finite | the advertised lifetime |
| two hours or less, not above what remains | two hours or less | unchanged |
| two hours or less, not above what remains | above two hours | two hours from now |
| above two hours | forever | the advertised lifetime |
| two hours or less | forever | two hours from the advertisement |

[*slaac.two-hour-rule]

When a prefix's preferred lifetime runs out, its addresses are
**deprecated**: kept on the interface for standing connections, with a
preferred lifetime of zero so that nothing new chooses them (§4.3). When
its valid lifetime runs out, the prefix and its addresses are removed.
[*slaac.deprecate-then-remove]

## Flags on the address

An address in a prefix advertised **on-link** (L set) is added normally,
so the kernel adds the prefix route. One advertised off-link is added
with `IFA_F_NOPREFIXROUTE`, so the kernel adds no prefix route for it.
[*slaac.off-link-gets-no-prefix-route]

## Temporary addresses [*slaac.temporary-addresses]

With `Address.Temporary` in the profile, each prefix also carries temporary
addresses (RFC 8981):

- one is formed with the prefix when the prefix arrives with a preferred
  lifetime above zero;
- its interface identifier is random, avoiding the reserved identifiers,
  the stable address and the prefix's other temporaries;
- its preferred lifetime is one day minus a random 0 to 599 s, so a rack
  of machines does not regenerate together, and its valid lifetime is two
  days. Each is cut to the prefix's own lifetimes.

When the newest temporary stops being preferred while the prefix still is, a
new one is formed. The old one stays, deprecated, until its valid lifetime
ends. A prefix keeps at most four temporaries, dropping the oldest beyond
that.

A temporary is deprecated when its own preferred lifetime or its prefix's has
run out, and removed when its own valid lifetime or its prefix's has.

`Address.Temporary` is read when router discovery starts. Changing it is a
profile edit, which restarts discovery (§3.3).
