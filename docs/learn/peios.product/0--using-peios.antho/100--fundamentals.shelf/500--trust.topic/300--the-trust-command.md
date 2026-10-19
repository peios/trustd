---
title: Understanding Trust Status
type: concept
description: Distinguish stored trust decisions from effective and cached roots.
related:
  - peios/trust/overview
  - peios/trust/adding-and-distrusting
  - peios/trust/the-compat-files
---

`trust` reads the effective store from trustd and records policy changes in
the registry. These are different views: a stored decision can exist before
the daemon or an application has applied it. `trust(1)` owns the command
reference, including arguments and exit statuses.

## Listing

`trust list` shows the effective roots. `trust list --distrusted` reads
durable
registry decisions. Compare both when checking a withdrawal.

`trust list --purpose ServerAuth` filters the service response by purpose.
It does not inspect rendered files. Healthy compatibility output uses the
same purpose filter, but a failed render can leave older files in place.

## Showing one root

`trust show` accepts a full fingerprint or unambiguous prefix from the
listing. An ambiguous prefix is refused. Inspect the full fingerprint,
source, and purposes before making a trust decision.

The `--pem` option emits only the certificate, suitable for export.
Exporting it does not change policy.

## Exit statuses

A command finding no matching root differs from a failed attempt to query
trustd. Scripts should check the exit status described in `trust(1)` rather
than treating every empty result as absence.

A successful registry write means the decision was recorded. Verify healthy
status and the effective store before treating it as applied. `trust reload`
returns failure when the refresh leaves degraded health.

## When a write is refused

`trust` has no additional authority to grant. Registry descriptors govern
changes, and trustd's control descriptor separately governs reload requests.
Have an authorized administrator perform the intended operation.

Editing generated certificate files is not a substitute for changing policy.
The next render replaces them, and other consumers can use the service
instead of those files.

## Reloading through the service manager

`svctl --wait reload trustd` sends SIGHUP. trustd processes it in its event
loop without replacing the main process. Repeated pending signals can be
combined into one refresh.

Inspect `trust status` afterward. Delivery of a service reload does not prove
that reading configuration, composing roots, or rendering files succeeded.
