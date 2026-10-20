---
title: Profiles
description: How netd resolves the profile tree — inheritance, Enabled, the accepted shapes of every value, what refuses the generation, and what a bare profile does.
---

The profile vocabulary — what each value means to an operator — is the network
policy reference's (`~peios/networking/network-policy-reference#profiles`).
This article is what netd does with it.

## Resolution

Every key under `Profiles\` is a profile, at every depth, named by its path
below `Profiles` with `/` between levels. The `Profiles` key's own values are
ignored. [*profile.every-key-is-a-profile]

Profiles are looked up case-insensitively: netd keys them by the lower-cased
path and keeps the path as written for display and for `Status Profile`.
[*profile.lookup-is-case-insensitive]

A key whose name is empty or contains `/` or `\` refuses the generation.

### Inheritance [*profile.inheritance]

A profile's effective values are its ancestors' values with its own laid over
them, per value name. A value a profile names replaces the inherited one whole
— a list replaces a list, never appends to it — and a value it does not name
is inherited. Value names compare case-insensitively, so `address.offered`
overrides `Address.Offered`.

Each profile is parsed from its own effective values. A malformed value in a
parent therefore refuses the generation at the parent, before any child is
reached.

### Enabled [*profile.enabled]

`Enabled` is a profile's switch, not a value: it is never inherited as one. A
profile is enabled when its own `Enabled` and every ancestor's say so; absent
means enabled. A child cannot re-enable itself under a disabled parent. A
disabled profile is still resolved and parsed — a malformed value in it still
refuses the generation — but a rule that names it abstains (§3.2).

`Enabled` accepts the boolean shapes below; anything else refuses the
generation.

## Accepted shapes [*profile.value-shapes]

Every value is parsed from its lowered form (§2.3):

| Shape | Accepted |
|---|---|
| boolean | an integer (non-zero is true), or a string `on`, `yes`, `true`, `1`, `off`, `no`, `false`, `0` in any case |
| number | a non-negative integer that fits 32 bits, or a string of one, surrounding space trimmed |
| list | a multi-string (empty items dropped), or a single string as a one-item list; an empty string is the empty list |
| string | a string, or an integer written as its decimal text |

A value of any other shape — a list where a boolean belongs, a binary value —
refuses the generation with the message
`profile <path>: <name> has the wrong shape`, where `<name>` is the value's
name in lower case.

## Values

| Value | Shape | What netd does with it |
|---|---|---|
| `Address.Offered` | boolean | runs a DHCPv4 client while IPv4 is in the families, and router discovery while IPv6 is |
| `Address.Families` | list | items `ipv4` and `ipv6`, in any case. The list replaces the default of both, so an empty list means neither family. Any other item refuses the generation. |
| `Address.Static` | list | each item `address/prefix`, either family, prefix at most 32 or 128. An item that does not parse refuses the generation. |
| `Address.LinkLocal` | boolean | link-local fallback (§5.5) |
| `Address.Temporary` | boolean | temporary IPv6 addresses (§6.2) |
| `Address.OnExpiry` | string | `Drop` or `Keep`, in any case. Anything else refuses the generation. |
| `Route.Offered` | boolean | takes the lease's gateway and classless routes and the routers' default route (§4.2) |
| `Route.Gateway` | list | each item an address of either family. The last IPv4 item is the IPv4 gateway, the last IPv6 item the IPv6 gateway. An item that does not parse refuses the generation. |
| `Route.Metric` | number | the metric of every route netd adds for the interface, and its place in DNS scope order |
| `Mtu.Offered` | boolean | takes the lease's MTU, else the routers' |
| `Mtu.Value` | number | the MTU to set. Below 68 refuses the generation. |
| `Hostname.Announce` | boolean | sends the machine's `Hostname` in DHCP option 12 |
| `Hostname.Offered` | boolean | adopts a lease's hostname when `Hostname` is unset (§8.4) |
| `Dns.Offered` | boolean | adds the network's DNS servers and search domains after the profile's own (§8.3) |
| `Dns.Servers` | list | each item an address of either family. An item that does not parse refuses the generation. |
| `Dns.Domains` | list | taken as written; nothing validates a domain |
| `Dns.Default` | boolean | present sets the scope's default-route flag; absent follows the interface's level (§8.3) |
| `Dns.Exclusive` | boolean | sets the scope's exclusive flag |

[*profile.values-as-tabled]

A value name not in this table (case-insensitively) refuses the generation
with `profile <path>: unknown value <name>`, the name as written.
[*profile.unknown-name-refuses]

After parsing, any `Address.Static` entry outside the profile's families
is dropped without an error: the family switch wins.
[*profile.statics-outside-families-dropped]

## A bare profile [*profile.bare-profile-does-nothing]

Every compiled default is false, empty or absent, apart from the families
(both) and `OnExpiry` (`Drop`). A profile that sets nothing therefore brings
its interface up and does nothing else: no clients, no addresses, no routes,
no DNS. The friendly behavior of the shipped `default` profile is four values
in its seed: `Address.Offered`, `Address.LinkLocal`, `Route.Offered` and
`Dns.Offered`, each `1`.
