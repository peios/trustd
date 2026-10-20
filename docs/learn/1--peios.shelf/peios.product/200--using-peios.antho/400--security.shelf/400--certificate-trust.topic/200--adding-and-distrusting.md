---
title: Adding and Distrusting Certificates
type: how-to
description: Record a trust decision and verify its effective result.
related:
  - peios/certificate-trust/overview
  - peios/certificate-trust/the-trust-command
  - peios/certificate-trust/the-compat-files
---

Add a certificate authority when the machine needs to trust an authority
outside the shipped set. Distrust a certificate to exclude it even if a
package or local addition supplies it.

## Before you start

- Install and start trustd and the `trust` command.
- Obtain write access to the relevant keys under
  `Machine\System\Trust\Certificates`.
- Verify the intended certificate's fingerprint through a trusted channel.
- Identify the applications affected by the change and how they obtain trust.

`trust(1)` owns command syntax. The regman entry for
`Machine\System\Trust\Certificates` owns the registry schema.

## In Security Policy

Use Security Policy's certificate views to inspect effective roots, additions,
and distrust decisions. Graphical changes use the same registry permissions
as `trust`. Verify the resulting store and affected applications after using
either interface.

## Trusting a certificate authority

1. Inspect `trust status` and `trust list` before making a change.
2. Obtain the intended certificate as a single PEM or DER file. The following
   example assumes it is saved as `corp-root.pem` in the current directory:

   ```sh
   trust add corp-ca corp-root.pem
   ```

3. Follow [Verify the Change](#verify-the-change).

The name identifies the local addition. The command rejects an invalid,
expired, or non-authority certificate before writing it. trustd validates
certificates again when composing the store.

To withdraw this named addition:

```sh
trust remove corp-ca
```

Removing an addition does not create a distrust decision. Another source
can still supply the same certificate.

### Purposes

An addition defaults to `ServerAuth`, used to validate TLS servers. Choose
other purposes only when intended. For example:

```sh
trust add corp-ca corp-root.pem --purposes ServerAuth,CodeSigning
```

Socket queries can filter by purpose. Compatibility bundles and hashed
files include only roots carrying `ServerAuth`. Applications using other
purposes must request and enforce the appropriate policy themselves.

## Distrusting a certificate authority

1. Find the intended certificate with `trust list` and inspect it with
   `trust show`. Compare the full SHA-256 fingerprint, not only its subject.
2. Run `trust distrust` with that fingerprint or its unambiguous prefix.
   Use `--reason` to record why it is being excluded; see `trust(1)`.
3. Check the durable decision with `trust list --distrusted`, then verify
   the effective result below.

A complete fingerprint can record a distrust before the machine has that
certificate. A later bundle or addition cannot make it trusted while the
distrust remains.

To remove a distrust, use `trust restore` with its fingerprint. Removing
the decision does not supply a certificate that is absent from both the
shipped bundle and local additions.

## Verify the change

1. Run `trust status`. Resolve degraded health using the procedure below.
2. Run `trust list`. For an addition, inspect its complete fingerprint,
   source, and purposes with `trust show`.
3. For a distrust, confirm that the root is absent from the effective set
   and that `trust list --distrusted` contains the decision.
4. Retest the affected application. If it caches trust, refresh that state
   using the application's documented procedure.

A registry write records intent. A socket query confirms the daemon's set.
Neither proves that a running application has discarded a cached root or
that compatibility rendering succeeded.

## Doing it from the registry

The `trust` command uses ordinary registry operations. A domain policy can
write the same keys; it does not need a separate trust mechanism.

When creating an addition manually, write `Certificate` last. trustd skips
an entry without that value so that the other metadata can be prepared
first. Use the regman schema rather than inferring value types from examples.

<!-- Preserve the published heading anchor. -->
<!-- lint-disable-next-line words -->
## Package-provided trust {#packages-may-offer-trust-never-take-it}

Package-provided trust decisions belong in inert registry seeds. Installing
files must not silently widen machine trust. Applying a seed is an explicit
image or administrative policy action.

A private application store is separate from the machine store. Its contents
and refresh behavior belong to that application's documentation.

## When the store is degraded

1. Read the error from `trust status` and preserve the failing operation or
   path for diagnosis.
2. Correct the cause. Repair a missing or invalid root bundle through its
   package. Correct an unreadable registry configuration or unintended
   distrust decision without restoring an intentionally excluded root.
3. If rendering failed, inspect the paths the affected application uses.
   Reported rendered paths can describe an earlier successful render; they
   are not a fresh inventory after failure. Do not edit generated files.
4. With trustd's control permission, run:

   ```sh
   trust reload
   trust status
   ```

5. Confirm healthy status, verify the intended change, and retest the
   application.

An authorized reload returns an error if refresh leaves degraded health.
The registry decision remains recorded. Service-manager reload uses SIGHUP;
its completion does not report the result of recomposition, so inspect
`trust status` afterward.

Skipped invalid certificates are reported separately from degraded health.
Read the warnings and correct the named entries before relying on them.
