---
title: Reading the Registry
description: What netd reads from Machine\System\Network, how values are lowered before anything interprets them, the depth limit, and what a registry change causes.
---

netd reads its configuration from `Machine\System\Network`, whole, every time
it reads it.

## What is read [*config.what-is-read]

| Value or key | Used for |
|---|---|
| `Hostname` (`REG_SZ`) | the machine's name (§8.4). An empty string counts as unset. |
| `ControlSecurity` (`REG_BINARY`) | the control object's descriptor (§9.1). An empty value counts as unset. |
| `Duid` (`REG_SZ`) | the machine's DHCP unique identifier, as hex (§5.7). Invalid hex rejects the configuration read. |
| `Rules\Interface\` and everything under it | the interface layer (§3.2) |
| `Profiles\` and everything under it | the profiles (§3.1) |

Nothing else under the key is configuration to netd. `Interfaces\` and
`Networks\` are read only for the values netd shares with the operator (§5.7,
§7.2), at the moment it needs them.

A missing `Machine\System\Network` means no configuration: no hostname, no
rules (so the backstop ignores every interface), no profiles.

## Lowering [*config.lowering]

Every value in the two trees is lowered to one of four shapes before anything
interprets it:

| Registry type | Lowered to |
|---|---|
| `REG_DWORD` (4 bytes) | an integer |
| `REG_QWORD` (8 bytes) | an integer |
| `REG_SZ`, `REG_EXPAND_SZ` | a string, cut at the first NUL; invalid UTF-8 rejects the read |
| `REG_MULTI_SZ` | a list of strings with empty items removed; invalid UTF-8 rejects the read |
| anything else, or a DWORD or QWORD of the wrong length | *other* |

The rule builder refuses an *other* by name (§3.2), and the profile parser
refuses it as a value of the wrong shape (§3.1), so an unusable value is never
silently dropped. The default (unnamed) value of a key is skipped in both
trees.

Values and subkeys are sorted by name, so two readings of an unchanged tree
compare equal.

The root of each tree is depth zero. A leaf at depth 16 is accepted, but
children below it reject the read instead of producing a partial tree.
[*config.tree-read-sixteen-deep]

A failed value query, failed child enumeration, unreadable child, or invalid
UTF-8 name rejects the entire read. An enumerated child that disappears before
it can be opened also rejects the read. Missing optional keys and values
remain valid absences; permission and I/O errors do not mean absence.

At startup, an incomplete read stops netd. During a reload, it logs the error
and retains the last complete configuration, including the control security
descriptor. The next registry notification triggers another attempt. This
completeness check does not turn separate registry calls into an atomic
snapshot: concurrent successful writes can still span a read.

## A registry change [*config.registry-change]

The watch is armed on the whole `Machine\System\Network` subtree. On any
event, netd reads the whole configuration again and compares it with what it
holds:

- If anything differs, the control object is rebuilt from
  `ControlSecurity`. If the rules or the profiles differ, a new
  generation is built (§3.2), and taken or refused.
- After a complete read, a full pass follows even if nothing differs.

netd's own writes to `Interfaces\` and `Networks\` come back through the same
watch. They cause a reload that finds nothing changed, and a pass that plans
nothing.

A failed read of the watch's events re-arms the watch.

There is no reload command: a write is noticed within the time it takes the
watch to deliver and a pass to run.
