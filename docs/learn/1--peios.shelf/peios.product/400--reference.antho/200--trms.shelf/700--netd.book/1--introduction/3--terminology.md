---
title: Terminology
description: The terms this manual uses for netd's own concepts — interface, joined, profile, generation, pass, desired state, network, scope,  and level.
---

Terms from the policy language — *rule*, *fact*, *verdict*, *backstop*,
*priority*, *exception* — mean what the network policy reference says. The
terms below are netd's own.

| Term | Meaning |
|---|---|
| **interface** | A kernel network link netd has seen, keyed by its kernel index while it exists and named in the registry by its interface id. |
| **interface id** | A UUID-shaped digest of an interface's bus path and MAC (§4.1). Stable across boots and kernel renames. |
| **verdict** | What the interface layer said about an interface: `JOIN(profile)`, `IGNORE`,  or `DOWN`. |
| **joined** (managed) | An interface whose verdict is `JOIN`. Loopback is never joined. Only joined interfaces get clients, contribute readiness, and appear in DNS snapshots. |
| **profile** | A resolved key under `Profiles\`, inheritance applied: how a joined interface stands on its network. |
| **generation** | One build of the interface layer and the profiles from one reading of the registry. netd holds the last good generation; a refused one changes nothing. |
| **pass** | One run of netd's converge sequence (§2.2): identify networks, judge links, start or stop clients, reconcile, publish. |
| **desired state** | What one interface should look like: up or down, its MTU, its addresses and its routes (§4.2). |
| **reconcile** | Diffing desired state against the kernel's and applying the difference (§4.3). |
| **network** | What is on the other side of a joined interface's carrier, identified from what it has offered (§7.1) and recorded under `Networks\<id>`. |
| **offer** | Everything a network has said: a DHCPv4 lease, router advertisements, a stateless DHCPv6 reply. |
| **level** | How far an interface has got toward being usable: `absent`, `link`, `addressed`,  or `routed` (§8.2). |
| **scope** | What one interface contributes to name resolution, as sent to resolvd (§8.3). |
