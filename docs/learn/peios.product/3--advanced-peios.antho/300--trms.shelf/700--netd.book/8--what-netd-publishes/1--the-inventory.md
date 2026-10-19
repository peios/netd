---
title: The Inventory
description: What netd writes under Interfaces\<id>\Status for every interface it has seen, when each value is set or removed, the descriptor on Status, and the values netd shares with the operator.
---

netd publishes observed network state in the registry. Ownership of each key
separates operator settings from the status that the daemon maintains.

## The record [*inventory.record]

Every non-loopback interface netd has seen has a key
`Machine\System\Network\Interfaces\<id>`, named by its interface id (§4.1).
netd creates it on the first pass that sees the interface. The key is the
operator's, apart from `ClientId`, a value both write (§5.7). netd's findings
are under its `Status` subkey.

Records are never deleted. The record of a card that has been removed stays,
with what netd last wrote.

## Status [*inventory.status-values]

| Value | Content | Present |
|---|---|---|
| `Name` | the kernel's name for the link | always |
| `Kind` | `wired`, `wireless`,  or `other` | always |
| `Mac` | the hardware address, lower-case, colon-separated | when the link has one |
| `Path` | the bus path | when there is one |
| `Driver` | the driver | when there is one |
| `Verdict` | `JOIN`, `IGNORE`,  or `DOWN` | when a rule spoke; removed when the backstop answered or rules tied |
| `Rule` | the path of the rule that spoke, or the tied rules as `<a> vs <b>` | when a rule spoke or rules tied; removed when the backstop answered |
| `Profile` | the profile path as written | `JOIN` only |
| `Readiness` | the interface's level (§8.2) | `JOIN` only |
| `Network` | the id of the network identified on the link now | while one is identified; removed when the carrier goes |
| `LastNetwork` | the id of the network the link last stood on | from the first identification; never removed |

[*inventory.value-presence]

Every value is `REG_SZ`. A value is written only when it differs from what is
there, and removed only when it is there, so a pass that changes nothing
writes nothing to the registry. [*inventory.writes-only-on-change]

`Status` is refreshed on every full pass for every non-loopback interface, and
again at each publish (§2.2) for joined ones, so `Readiness` follows a
reconcile that moved it without any link event.

`Status Network` is read by the kernel to give the packet layers their
`Network.*` facts (PKM §6.5). It names the network only while netd has
identified one on the link (§7.1).

## The descriptor [*inventory.status-descriptor]

`Status` is created with the descriptor `O:SYG:SYD:P(A;;KA;;;SY)(A;;KR;;;WD)`:
SYSTEM has full control, Everyone has read access, and the DACL is protected,
so the hive root's inheritable grant to Administrators does not reach it. Only
netd, as SYSTEM, can write there. An administrator's hand edit is refused at
the write, not reverted at the next pass. The descriptor is set only when netd
creates the key.

## The machine's values

On `Machine\System\Network` itself netd writes:

- `Readiness`, the machine level (§8.2);
- `Duid`, when it was absent and netd generated or read one (§5.7).
