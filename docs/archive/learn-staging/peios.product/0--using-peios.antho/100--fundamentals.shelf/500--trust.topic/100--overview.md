---
title: The trust store
type: concept
description: Inspect machine trust, find the guide for adding or distrusting a certificate authority, verify the effective result, and diagnose degraded trust-store health.
related:
  - peios/trust/the-trust-command
  - peios/trust/adding-and-distrusting
  - peios/linux-compatibility/name-service-switch
  - peios/registry-administration/regman
---

Start with `trust status` to inspect the machine's trust store before changing it.

Programs that use the machine's TLS trust get their certificate authorities
from **trustd**, the trust store. A program with its own private trust store
is separate; see [packages and private trust stores](~peios/trust/adding-and-distrusting#packages-may-offer-trust-never-take-it).

## Choose your task

| What you need to do | Start here |
|---|---|
| Check store health or inspect a certificate authority | [Seeing what is in force](#seeing-what-is-in-force), then the [trust command reference](~peios/trust/the-trust-command) |
| Add or distrust a certificate authority | Check [who may change it](#who-may-change-it), then follow [Adding and distrusting certificates](~peios/trust/adding-and-distrusting) |
| Check that a change took effect | [Verify the change](~peios/trust/adding-and-distrusting#verify-the-change); a recorded registry decision alone is not proof that consumers use it |
| Investigate degraded health | [When the store is degraded](~peios/trust/adding-and-distrusting#when-the-store-is-degraded) |

## Seeing what is in force

Start with `trust status` to check the store's health and whether the
compatibility files are enabled:

```
$ trust status
generation   7
health       ok
roots        121 in force
  shipped    121
  added      0
  distrusted 0
compat       GenerateLinuxTrustFiles = 1
  rendered   /system/retc/ssl/certs/ca-certificates.crt
  rendered   /system/retc/ssl/cert.pem
```

`generation` increases every time the store changes, so a program holding
a copy can tell whether it is current without fetching it again.
`health` is `degraded` when composition or compatibility-file rendering
failed — see
[when the store is degraded](~peios/trust/adding-and-distrusting#when-the-store-is-degraded).

Use `trust list` for the roots in force and `trust show <fingerprint>` for
one root's full fingerprint, source and purposes. `trust list --distrusted`
shows the registry's distrust decisions; it does not by itself prove that
trustd has applied them. After a change, [verify the effective
store](~peios/trust/adding-and-distrusting#verify-the-change).

## Who may change it

`Machine\System\Trust\Certificates` and its subkeys, like any registry
key, are governed by their own security descriptor. By default SYSTEM and
Administrators may write; everybody may read. That descriptor is the
*only* gate: [`trust`](~peios/trust/the-trust-command) and `reg` write the
same values through the same check, so there is no second permission model
to keep in step with the first.

Reading is open to everyone, because the root set is public — in the
default configuration it is sitting in a world-readable file.

## Where trust policy comes from

trustd composes that set from two inputs and serves the result.

| Input | Where it lives | Who changes it |
|---|---|---|
| Mozilla's root store | `/usr/share/ca-certificates/mozilla.crt`, shipped by the `ca-certificates` package | An upgrade of that package |
| Additions and distrusts | `Machine\System\Trust\Certificates` in the registry | An administrator, or the domain |

The split is the whole design. The roots are **package data** — a hundred
and twenty-odd certificates nobody on this machine decided anything about
— and package upgrades already do the right thing with them, including
removing a root Mozilla has withdrawn. The registry holds **decisions**:
each entry is something somebody chose, which is what keeps an audit of
`Machine\System\Trust` worth reading.

## What programs actually read

The store itself is a socket, `/run/trustd/trust.sock`. Peios-native
programs can ask it directly and subscribe to changes. A running program
must refresh its own trust state when it receives an update; socket
publication alone does not prove that every consumer stopped using a
cached certificate.

Almost nothing does that yet, so trustd also *renders* the store to the
files the portable software ecosystem expects:

```
/etc/ssl/certs/ca-certificates.crt   the bundle Go and most software read
/etc/ssl/cert.pem                    OpenSSL's default CAfile
/etc/ssl/certs/<hash>.0              OpenSSL's default CApath
```

Those files are a **copy of an answer**, not the answer. Editing one does
not change trustd's policy, and trustd overwrites it the next time anything
changes. Use `trust` or Security Policy to make a lasting change. The
`GenerateLinuxTrustFiles` value decides whether they exist at all — see
[the compat files](~peios/trust/the-compat-files).

Installing the root-store package alone renders nothing; the image that
runs programs using machine trust must provide the service that composes
and renders it. Conversely, trustd being absent or stopped does not prove
that previously rendered files are absent or current. Inspect the actual
consumer paths and service health rather than inferring trust from the
daemon's presence alone.

> [!NOTE]
> There is no `update-ca-certificates` and no directory to drop a `.crt`
> into. Both exist on other systems because trust policy lives in files
> there; here it lives in the registry, where changing it is an access
> check against a key's descriptor rather than a question of who can write
> to a directory.

## Composition is all or nothing

If the shipped bundle cannot be read, yields implausibly few roots, or
would leave no usable roots, composition fails before a new set is
installed. The inspected [trustd 0.1.6 source](https://github.com/peios/trustd/blob/2fd7d86aac00e207320bda1ae11045aec3d61fbf/trustd/src/main.rs#L114-L146)
leaves the previous in-memory set and rendered files untouched in that
case and reports degraded health. On a first start, there may be no
previous in-memory set or rendered files to retain.

Rendering is a separate step. In that source, the socket's new set is
installed before the compatibility files are written, and a rendering
failure does not roll it back. The files can therefore disagree with the
socket or with one another. Composition's all-or-nothing check is not a
transaction across every trust consumer; see [the rendering
limits](~peios/trust/the-compat-files#three-artifacts-because-the-ecosystem-does-not-agree)
and [degraded-store diagnosis](~peios/trust/adding-and-distrusting#when-the-store-is-degraded).
This is a pinned source finding, not verification of an installed image.

A single bad *entry* is different. An addition that is not a certificate,
is not a CA, or has expired is skipped with a warning and everything else
proceeds — one administrator's typo does not take the machine's trust
down.

## What is recorded

Each time the set of roots in force changes, trustd writes one event per
root that entered or left it:

| Event | When |
|---|---|
| `trustd.root.added` | A root entered the set: an addition, a distrust lifted, or a root a bundle upgrade brought in |
| `trustd.root.distrusted` | A distrust took a root out of the set |
| `trustd.root.removed` | A root left the set for any other reason: its addition was withdrawn, or a bundle upgrade dropped it |

Each carries the certificate's SHA-256 fingerprint in
`object.certificate.digest`, its subject name in `object.certificate.name`,
and what it is trusted for in `object.certificate.purposes`, written in
kebab-case (`ServerAuth` becomes `server-auth`). Search by the digest: it
is the only one of the three that identifies a certificate.

The records say what changed, not who changed it. An addition or a
distrust is a registry write, recorded by the registry itself where the key
is audited, and a bundle upgrade is a package operation, recorded by peipkg.
The set trustd composes when it starts is not recorded, so a change made
while trustd was not running is seen only as part of that starting set.
The events are `standard`, so the emission policy can switch them off.

## What trustd is not

**It holds no private key.** Not the machine's, not anybody's. A service
that holds keys is a signing oracle if it is ever compromised, and wants
almost the opposite security posture from one whose socket is open to
every program on the machine. Machine identity — the certificates and keys
a machine presents when *it* is the server — is a separate concern, and
will be a separate service.

**It does not fetch anything.** No root is downloaded on demand and no
revocation list is retrieved, in this version. What the machine trusts
changes when a package is upgraded or somebody writes to the registry, and
at no other time.
