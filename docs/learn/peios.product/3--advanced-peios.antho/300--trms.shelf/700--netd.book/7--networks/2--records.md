---
title: Records
description: The Networks\<id> record — what netd writes under its Status, what the operator writes on the record, and how the two are read.
---

Every network a joined interface has been identified on gets a record,
`Machine\System\Network\Networks\<id>`. Records are never deleted by netd.
[*netrec.never-deleted]

## What netd writes [*netrec.status-values]

On every identification (§7.1), netd creates the record if it is missing and
writes these values under its `Status` subkey, each only when it differs from
what is there:

| Value | Type | Content |
|---|---|---|
| `Kind` | `REG_SZ` | the interface kind it was seen on |
| `Server` | `REG_SZ` | the DHCPv4 server; removed when there is none |
| `Gateway` | `REG_SZ` | the lease's gateway; removed when there is none |
| `Router` | `REG_SZ` | the IPv6 default router; removed when there is none |
| `Prefixes` | `REG_MULTI_SZ` | the subnet and the autoconfigured prefixes, CIDR form |
| `DnsServers` | `REG_MULTI_SZ` | the DNS servers offered, either family |
| `LastSeen` | `REG_SZ` | the wall-clock time of the identification, in Unix seconds |
| `LastInterface` | `REG_SZ` | the kernel name of the interface it was seen on |

`LastSeen` is rewritten on every pass that identifies the network, so a
record's `Status` changes whenever netd runs a pass on a link that is on it.

`Status` is created with the descriptor `O:SYG:SYD:P(A;;KA;;;SY)(A;;KR;;;WD)`
: SYSTEM has full control and Everyone has read access. It is protected, so
the hive root's inheritable grants do not reach it, and a hand edit is refused
rather than silently reverted at the next pass. The descriptor is set only
when netd creates the key; a `Status` key that already exists keeps whatever
descriptor it has. [*netrec.status-descriptor]

## What the operator writes [*netrec.operator-values]

On the record itself, not under `Status`:

| Value | Read as | Meaning |
|---|---|---|
| `Name` | `REG_SZ`, empty is unset | the `Network.Name` fact |
| `Trust` | `REG_SZ`, empty is unset | the `Network.Trust` fact |
| `RequestedAddress` | `REG_SZ`, an IPv4 address | the address the next DHCPv4 client asks for first (§5.7); netd writes it too |

`Name` and `Trust` are read at every identification, so an edit reaches the
interface layer on the pass that follows the registry write (§2.3). They are
opaque: netd compares nothing about them and gives them no vocabulary.
[*netrec.name-and-trust-are-read-each-pass]

The kernel reads `Name` and `Trust` itself, from the record that an
interface's `Status Network` names (PKM §6.5).
