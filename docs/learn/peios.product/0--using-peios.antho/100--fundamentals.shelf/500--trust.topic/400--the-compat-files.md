---
title: The Compatibility Trust Files
type: concept
description: How trustd supplies file-based trust and what rendering failures mean.
related:
  - peios/trust/overview
  - peios/trust/adding-and-distrusting
---

trustd renders certificate files for programs that obtain machine trust from
a path. The files are derived output, not configuration. Change trust through
the registry or `trust`; manual edits are replaced on the next render.

## Three artifacts, because the ecosystem does not agree

| Path | Purpose |
|---|---|
| `/etc/ssl/certs/ca-certificates.crt` | Certificate bundle |
| `/etc/ssl/cert.pem` | Alternate bundle path |
| `/etc/ssl/certs/<subject-hash>.0` | Hashed certificate lookup |

Roots with the same subject hash use successive numeric suffixes. Updating
only a bundle would leave hashed lookups using stale roots, so trustd
rebuilds the certificate directory as well.

Only roots with `ServerAuth` are rendered. Purpose metadata is not embedded
as a substitute for application validation; each consumer still applies its
certificate rules.

## Publication and failure

The renderer prepares a replacement certificate directory and attempts an
atomic exchange. Where exchange is unavailable, it uses renames with rollback.
The fallback can temporarily leave the directory absent. A rollback failure
can require repair.

The directory and alternate bundle are separate operations, and the service
publishes its effective set before rendering. No single atomic switch covers
the socket and every file. A failure can therefore leave consumers observing
different generations.

Follow [degraded-store
recovery](~peios/trust/adding-and-distrusting#when-the-store-is-degraded)
and check the actual paths used by the application. A previously reported
rendered path is not proof of its contents after a failed refresh.

## Turning them off

`MachineSystemTrust GenerateLinuxTrustFiles` selects whether trustd supplies
compatibility files. Its regman entry owns the value reference.

Turning file output off removes trust inputs from programs that require
those paths. Use that mode only when the installed applications use the
service or deliberately managed private stores. The socket continues serving.

Removal itself uses several filesystem operations and can fail partway.
A stored setting does not prove that all files were removed. Check service
health, the relevant paths, and application behavior after changing the mode.

To restore ordinary file output:

```sh
reg set Machine/System/Trust GenerateLinuxTrustFiles dword:1
trust reload
trust status
```

These operations require registry write access and trustd's control right.
Confirm healthy status and retest the application.

## Why a copy, when name resolution gets a pointer

A resolver configuration can name a service that answers later requests.
A certificate bundle has to contain the authorities itself. It cannot direct
a consumer to ask trustd instead, which is why file consumers need a rendered
copy and their own refresh behavior.

The effective roots are public, so generated files are readable by ordinary
programs. Changing the policy remains protected by registry permissions.
