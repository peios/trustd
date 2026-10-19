---
title: The trust command
type: reference
description: Every verb of the trust command — what it reads, what it writes, and what its exit statuses mean.
related:
  - peios/trust/overview
  - peios/trust/adding-and-distrusting
---

`trust` is the trust store's operator command. It **reads the effective
store over trustd's socket and writes decisions to the registry**. Start
with `trust status` for health, `trust list` for the roots in force, and
`trust show <fingerprint>` for one root's details.

The registry holds local additions and distrusts, not the shipped roots.
`trust list --distrusted` reads those decisions directly. Writes made with
`trust` and `reg` pass through the same access check. For changes and
verification, follow [adding and distrusting
certificates](~peios/trust/adding-and-distrusting).

## Verbs

| Command | Reads | Writes |
|---|---|---|
| `trust list [--purpose P]` | socket | — |
| `trust list --distrusted` | registry | — |
| `trust show <fingerprint> [--pem]` | socket | — |
| `trust status` | socket | — |
| `trust add <name> <file\|-> [--purposes A,B]` | the file | registry |
| `trust remove <name>` | — | registry |
| `trust distrust <fingerprint\|file> [--reason R]` | socket, then | registry |
| `trust restore <fingerprint>` | registry | registry |
| `trust reload` | — | — (asks trustd to recompose) |

## Listing

```
$ trust list
018e13f0772532cf  shipped    CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US
0a81ec5a929777f1  shipped    CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R3
4f2ab19c8e10dd77  added:corp-ca  CN=Corp Issuing CA,O=Example Ltd,C=GB

121 root(s)
```

The first column is the first sixteen characters of the SHA-256
fingerprint, and every verb that takes a fingerprint accepts that prefix —
what is printed can be pasted back in. An ambiguous prefix is refused
rather than guessed at.

`--purpose ServerAuth` narrows the socket listing to roots carrying that
purpose. It is not an inventory of the compatibility files: the inspected
renderer does not filter them by purpose. See the [source-qualified
limitation](~peios/trust/adding-and-distrusting#purposes).

## Showing one root

```
$ trust show 4f2ab19c
subject      CN=Corp Issuing CA,O=Example Ltd,C=GB
fingerprint  4f2ab19c8e10dd77…
source       added
added as     corp-ca
purposes     ServerAuth
expires      2074003199

-----BEGIN CERTIFICATE-----
…
```

`--pem` prints the certificate alone, for piping into a file or another
tool.

## Exit statuses

| Status | Meaning |
|---|---|
| `0` | Done. |
| `2` | Asked about something that is not there — no root matches, no such addition, not distrusted. |
| `1` | It went wrong: the daemon is unreachable, the file is not a certificate, the registry refused the write. |
| `64` | The command line was not understood. |

The separation of `2` from `1` is what lets a script tell "this machine
does not trust that CA" from "I could not find out". A successful write
means the decision was recorded; [verify the effective
store](~peios/trust/adding-and-distrusting#verify-the-change) before treating
the change as applied. Likewise, a successful `trust reload` means the
request was accepted: the [inspected daemon](https://github.com/peios/trustd/blob/2fd7d86aac00e207320bda1ae11045aec3d61fbf/trustd/src/main.rs#L243-L246)
returns success even when refresh left degraded health. Read `trust
status` afterwards.

## When a write is refused

```
$ trust distrust 018e13f0772532cf
trust: not permitted to change Machine\System\Trust\Certificates\Distrust —
       changing what this machine trusts is governed by that key's descriptor
```

`trust` has no privilege of its own to grant. Changing the machine's trust
is a registry write, and whether you may make it is decided by the key's
security descriptor — the same answer `reg` would get. Ask an administrator
with write access to make the intended change; editing a generated
certificate file is not a substitute.

`trust reload` is a service-control request, not a registry write. Its
permission is separate from permission to change trust decisions; Security
Policy exposes trustd's `ControlSecurity` under **Settings → Trust Service**.

## Reloading through the service manager

`svctl --wait reload trustd` and the service manager's Reload action send
SIGHUP to trustd. The daemon consumes it in its normal event loop and uses
the same recomposition path as `trust reload`, without replacing its main
process. Repeated pending signals may be coalesced into one refresh.

Check `trust status` for the resulting health. A service reload completing
does not prove that recomposition succeeded; on failure, trustd retains its
last rendered store and reports degraded health. Older daemon versions that
do not handle SIGHUP can terminate on service reload; use `trust reload`
directly until the updated daemon is installed.
