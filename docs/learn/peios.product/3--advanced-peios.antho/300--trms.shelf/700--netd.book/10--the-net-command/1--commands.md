---
title: Commands
description: The net command as built — each subcommand, what it reads, how net wait and net policy wait decide, and its exit statuses.
---

`net` is netd's operator command. It talks to netd over the control socket,
and reads the registry directly for `rules` and `profiles`, because those are
configuration that netd merely executes. Changing the network is a registry
write; `net` shows state and pokes the daemon. The task-oriented guide is
`~peios/networking/the-net-command`.

## Subcommands [*net.subcommands]

| Command | Does |
|---|---|
| `net status` | prints the status reply (§9.2) |
| `net renew <interface>` | sends `renew` |
| `net reconcile` | sends `reconcile` |
| `net rules` | prints `Rules\Interface` from the registry: one line per rule, indented by depth, with its priority, `(disabled)` for `Enabled = 0`, its conditions, and its actions (`NULL` when it has none) |
| `net profiles`, `net profile list` | prints `Profiles\` from the registry: one line per profile, indented by depth, with the values it sets itself (`(inherits only)` when none) and `(disabled)` |
| `net wait <link\|addressed\|routed> [seconds]` | waits for the machine level |
| `net policy` | prints the kernel engine's status: enforcing or not, the generation, unwalked changes, a refused last walk, the context count |
| `net policy wait [seconds]` | waits for the packet policy to be in force |
| `net version`, `net --version` | prints `net <version>` |

`rules` and `profiles` fail when their key does not exist. Neither needs netd
running.

## `net status` output [*net.status-output]

A `hostname` line (`(unset)` when empty) and a `readiness` line, then
`policy     REFUSED: <why> (the last good generation stands)` when there is a
refusal. Then a block per interface: `<name>  [<id>]`, then `verdict`
(`<VERDICT>(<profile>) by <rule>`, or `(none) by <rule>`), `state`, and
`readiness` for a joined interface. Then, where present, `hardware`, `network`
(`<name> [<id>] trust <trust>`), each `address`, `gateway`, `gateway6`, `dns`,
`search`, `lease` (`<state> from <server>, <n>s left`) and `warning`.

## `net wait` [*net.wait]

It asks for `status` every 500 ms and succeeds as soon as the machine level is
at least the one named. An error reaching netd is printed and the wait goes
on. The timeout is the second argument, or 60 s when absent or not a number.
When it lapses, `net` prints `net: timed out waiting for <level>` and fails.

`absent` is accepted as a level, and is met at once.

## `net policy wait` [*net.policy-wait]

It reads `/dev/peios-ntfe`'s status (ABI 5) once and takes the number of
policy changes the engine has noted as its target. It then polls every 5 ms
until the engine's count of changes walked reaches the target. If the last
walk was refused, it fails, naming the errno and the generation that stands;
otherwise it succeeds. The timeout is the argument, or 10 s. The counters are
the kernel's (PKM §6.5). A device that answers with another ABI fails at once.

## Exit status [*net.exit-status]

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | netd unreachable, an error reply, a timeout, a refused policy, or a registry key that cannot be opened |
| 2 | usage: an unknown subcommand, a wrong argument count, an unknown level, or a non-numeric `policy wait` timeout |

## Wait deadlines

`net wait` limits each status request and polling pause to the remaining
wait deadline. A zero timeout expires without sending a status request.
Unrepresentable timeouts return an error instead of panicking. `net policy
wait` also rejects unrepresentable deadlines; its kernel status reads remain
synchronous.
