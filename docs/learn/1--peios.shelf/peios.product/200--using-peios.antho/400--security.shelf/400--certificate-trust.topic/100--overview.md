---
title: The Trust Store
type: concept
description: How trustd combines shipped roots with local trust decisions.
related:
  - peios/certificate-trust/the-trust-command
  - peios/certificate-trust/adding-and-distrusting
  - peios/certificate-trust/the-compat-files
  - peios/using-peios/registry/regman
  - peios/certificate-trust/security-policy
---

trustd supplies the machine's trusted certificate authorities. It combines
shipped roots with registry decisions, then publishes the effective set
through a local service and compatibility files.

A program with its own private trust store uses separate policy. Changing
the machine store does not establish that every application changed its
trust decisions.

## Seeing what is in force

`trust status` reports health, generation, root counts, and compatibility
output. `trust list` reports the effective roots served by trustd.

The generation identifies the published set. Programs holding a snapshot
can use it to detect a change. Health is `degraded` when reading,
composition, or compatibility output fails. It is not safe to infer successful
publication from the registry alone.

`trust list --distrusted` reads durable registry decisions. It does not prove
that the daemon has applied them. See
[Adding and Distrusting Certificates](~peios/certificate-trust/adding-and-distrusting)
for changes and verification.

<!-- Preserve the published heading anchor. -->
<!-- lint-disable-next-line spelling -->
## Who can change it {#who-may-change-it}

The security descriptors on `Machine\System\Trust\Certificates` and its
subkeys control registry writes. SYSTEM and Administrators have write access
under the default policy; everyone can read. The `trust` command and library
use the caller's authority. They do not grant permission to change trust.

Reloading trustd has a separate control permission. A caller can have
permission to record a decision without permission to request a reload.
The daemon also watches for registry changes.

## Where trust policy comes from

| Input | Location | Updated by |
|---|---|---|
| Shipped roots | `/usr/share/ca-certificates/mozilla.crt` | Root-store package updates |
| Additions and distrusts | `Machine\System\Trust\Certificates` | Registry policy |

The package supplies certificates; the registry records decisions about
them. A distrust can exclude a shipped root without modifying the package.
An addition supplies a certificate that the shipped set does not contain.

A root's fingerprint identifies the certificate. Subject names alone do
not distinguish certificates reliably. Purpose metadata records the uses
for which an addition is trusted.

## What programs actually read

Native clients use `libtrust.so` to query or subscribe to
`/run/trustd/trust.sock`. A subscription publishes complete generations.
Applications must replace their own cached trust state when appropriate;
a notification does not itself invalidate an application's existing sessions.

Compatibility consumers read generated bundles or a hashed directory under
`/etc/ssl`. Those outputs contain roots permitted for `ServerAuth`.
They are derived from policy, so editing them does not make a lasting change.
See [The Compatibility Trust Files](~peios/certificate-trust/the-compat-files).

Installing a root bundle alone does not compose or render the machine store.
Likewise, stopping trustd does not remove an existing rendered bundle or
invalidate a program's cached copy.

## Failure and recovery

If a complete configuration read or composition fails, trustd retains its
previous effective set and reports degraded health. Missing optional values
retain their documented defaults. An incomplete addition without a
`Certificate` value is skipped while it is being created.

Compatibility rendering happens after the effective socket set changes.
A rendering failure can leave different consumers using different sets.
Inspect the failure and verify both the service and the paths used by the
affected application. See
[When the Store Is
Degraded](~peios/certificate-trust/adding-and-distrusting#when-the-store-is-degraded).
