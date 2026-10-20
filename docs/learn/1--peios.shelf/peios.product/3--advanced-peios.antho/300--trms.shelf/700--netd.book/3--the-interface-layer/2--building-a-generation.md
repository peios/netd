---
title: Building a Generation
description: How netd turns Rules\Interface and Profiles\ into a generation with pnp-core — the JOIN of a disabled profile, what refuses a generation, lints, and what a refusal leaves in force.
---

A generation is built whenever the rules or the profiles have changed (§2.3),
and once at startup.

## The order of the build

1. **Profiles** are resolved (§3.1). Any error refuses the generation.
2. If `Rules\Interface` does not exist, the generation has no forest.
   Every interface meets the backstop, `IGNORE`, and the profiles are
   kept for nothing to name. [*generation.no-rules-means-backstop]
3. Each subkey of `Rules\Interface` is a root rule. Its tree is lowered
   to `pnp-core`'s input and built as the `Interface` layer with
   `build_forest` — the same ingestion, condition parsing, and lints the
   kernel applies to the packet layers (PKM §6.5). Every build error
   refuses the generation.
4. Every profile a `JOIN` names is looked up. A `JOIN` naming no profile
   refuses the generation with `JOIN(<path>) names no profile`.
   [*generation.dangling-join-refuses]

## Lowering a rule

Integers and strings pass through. A value of any other lowered shape (§2.3)
refuses the generation with
`rule <path>: value <name> has an unsupported type`.

A list is passed through item by item, except in `Actions`. There, an
item that is a `JOIN` naming a profile that exists and is **disabled** is
replaced by `NULL` before the build, so the rule abstains and the
forest's own collation answers without it: its parent, another tree, or
the backstop. A `JOIN` of a disabled profile is not a fault.
[*generation.join-of-disabled-profile-abstains]

A `JOIN` target is recognized loosely. Whitespace anywhere is ignored, `JOIN(`
matches in any case, `\` in the path is read as `/`, and the path is compared
case-insensitively. So `join ( Office\London )` names the profile
`office/london`. [*generation.join-target-recognized-loosely]

## What refuses a generation

Everything `pnp-core` refuses at the interface layer refuses it here, with
netd's wording:

| Cause | Message |
|---|---|
| An unknown fact in a condition | `rule <path>: unknown fact <key>` |
| A malformed operator | `rule <path>: bad operator in <key>` |
| A malformed pattern | `rule <path>: bad pattern in <key>` |
| `Actions` not a list | `rule <path>: Actions is not a list` |
| A malformed action | `rule <path>: bad action (…)` |
| An action the interface layer does not speak (`PASS`, `DROP`, `TAG`, …) | `rule <path>: an action the interface layer does not speak` |
| A key that does not exist at the interface layer | `rule <path>: <key> does not exist at the interface layer` |
| `Present` on a fact never present at this layer | `rule <path>: <key> on a fact that never exists at this layer` |
| `Priority` not an integer | `rule <path>: Priority is not an integer` |
| `Enabled` not 0 or 1 | `rule <path>: Enabled is not 0 or 1` |
| A malformed rule name | `rule <path>: bad name` |
| A `JOIN` naming no profile | `JOIN(<path>) names no profile` |
| A malformed profile | the profile parser's message (§3.1) |

The depth of a rule tree refuses nothing. It is bounded only by netd's
registry read, which takes rules to 16 levels below `Rules\Interface` and
ignores anything deeper (§2.3).

[*generation.refusal-causes]

A condition on a fact that exists in the vocabulary but can never be
present at the interface layer, such as `DstPort`, is not refused. It is
a **lint**: logged as a warning, `rule <path>: <key> can never hold at
the interface layer`, and the generation is taken.
[*generation.never-at-layer-is-a-lint]

## A tie refuses at runtime

A generation built while netd is running is judged against every non-loopback
interface before it is taken. If any interface meets a **conflict** (two rules
tied on priority naming different profiles, §3.3), the generation is refused
with `rules <a> vs <b> tie on interface <name>`.
[*generation.runtime-tie-refuses]

## Taken or refused

A taken generation replaces the old one whole, clears any recorded refusal,
and is logged with its counts of rule trees and profiles. The pass that
follows judges every interface against it.

A refused generation changes nothing. The last good generation stays in force,
netd logs `interface layer refused: <why>; the last good generation stands` at
error level, and records the reason, which `status` reports as `refusal` and
`net status` prints as a `policy REFUSED` line.
[*generation.refusal-keeps-last-good-and-is-reported] The refusal stays
recorded until a generation builds.

The interface layer's refusal is netd's alone. The kernel reads the packet
layers from the same registry state and refuses or takes them on its own (PKM
§6.5): a dangling `JOIN` never stalls the firewall, and a bad `Flow` rule
never stops an interface joining.
