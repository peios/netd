---
title: Requests
description: The control socket's framing and limits, its four requests and the rights they need, the errors it answers with, and every field of the status reply.
---

Control requests use the shared framing and reply types described here. Each
operation names the right required by the daemon.

## Framing [*control-req.framing]

The control socket is a PSPU observability query channel: one length-prefixed
MessagePack map in each direction, one request and one reply per connection,
except `subscribe`.

- A frame is a 4-byte little-endian payload length, then the payload.
- A length above 65536 is refused before any of the payload is read, with
  `{ok: false, error: "message of <n> bytes exceeds the ceiling"}`.
- A request is a map with a string `query`. Unknown keys are ignored, and
  a key that appears twice refuses the request.
- A reply is a map with a boolean `ok`, and either the result's fields or
  a string `error`.

An oversized, incomplete-at-EOF, or undecodable request is answered with an
error reply and the connection ends:

| Problem | `error` |
|---|---|
| no `query` | `missing field query` |
| an unknown `query` | `unknown query "<query>"` |
| a duplicate key | `duplicate field <key>` |
| `renew` without `interface` | `missing field interface` |
| malformed MessagePack | `malformed message: …` |

[*control-req.decode-errors]

Expired client deadlines and failed socket I/O close the connection without a
reply (§9.1). A normal reply that exceeds the message ceiling is replaced with
an error reporting its size.

## The requests [*control-req.requests]

| `query` | Right | Does | Reply |
|---|---|---|---|
| `status` | `NETWORK_QUERY` | nothing | the status (below) |
| `subscribe` | `NETWORK_QUERY` | keeps the connection as a subscriber (§8.3) | a snapshot now, and another on each change |
| `reconcile` | `NETWORK_CONTROL` | a full pass (§2.2) | `{ok: true}` |
| `renew`, with `interface` | `NETWORK_CONTROL` | the client renews (§5.4) | `{ok: true}`, or an error |

`renew` finds its interface by kernel name or by interface id. It answers
`no interface <name>` when there is none, and `<name> is not using DHCP` when
the interface has no DHCPv4 client. [*control-req.renew-errors]

## The status reply [*control-req.status-fields]

| Field | Content |
|---|---|
| `hostname` | the name netd last set, empty if none (§8.4) |
| `level` | the machine level (§8.2) |
| `refusal` | why the newest generation was refused, or nil (§3.2) |
| `interfaces` | one map per non-loopback interface netd has seen, joined or not, in kernel index order |

Each interface:

| Field | Content |
|---|---|
| `ifid`, `name`, `index` | the interface id, kernel name,  and index |
| `mac`, `path`, `driver` | identity (§4.1); empty strings when absent |
| `verdict` | `JOIN`, `IGNORE`,  or `DOWN`; nil when the backstop answered or rules tied |
| `rule` | the rule that spoke, `backstop`, or the tied rules `<a> vs <b>` |
| `profile` | the profile path, `JOIN` only |
| `network`, `network_name`, `network_trust` | the network identified now (§7) |
| `warning` | discovery unanswered (§5.2), or a tie (§3.3); nil otherwise |
| `up`, `carrier` | the link's flags |
| `level` | the interface's level (§8.2), computed for every interface |
| `addresses` | every address the kernel holds, `address/prefix`, link-local ones included |
| `gateway`, `gateway6` | the gateway of the interface's first IPv4 and IPv6 default route, any owner's |
| `dns`, `search` | the merged DNS facts (§8.3); empty for an interface not joined |
| `lease` | while the client holds a lease: `server`, `expires_in` (whole seconds), `state` (§5.1), `duration` (the lease's length), and `renew_at` and `rebind_at` (T1 and T2), the last three in whole seconds after the lease was bound; nil otherwise. A client reading a netd that predates the last three finds them absent. |

[*control-req.status-interface-fields]
