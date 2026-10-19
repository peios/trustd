---
title: Adding and distrusting certificates
type: how-to
description: Trust a certificate authority the shipped set does not include, stop trusting one it does, with the trust command or Security Policy on the desktop, and understand what happens when the store cannot be composed.
related:
  - peios/trust/overview
  - peios/trust/the-trust-command
  - peios/registry-administration/regman
---

Two things can be decided about this machine's trust, and both are values
under `Machine\System\Trust\Certificates`. Change them with `trust` on a
terminal, or **Security Policy** on the desktop (type `security` in the
launcher), which takes the same steps.

Before making a change, check `trust status` and `trust list`. You need
write access to the relevant registry key; by default SYSTEM and
Administrators may write, and everybody may read. See [who may change
it](~peios/trust/overview#who-may-change-it).

## In Security Policy

Security Policy's **Certificates** sections show what `trust status`,
`trust list` and `trust list --distrusted` show, and change it.

- **Trusted** lists every certificate authority in force, those shipped
  with Peios and those added on this machine, with a search above them.
  Opening one shows who issued it, when it is valid, its key, serial number
  and SHA-256 fingerprint, and what it is trusted for. **Export…** saves
  it as a PEM file. **Distrust…** stops trusting it, and **Remove…** takes
  back one this machine added; both ask first, under their row.
- **Add Certificate…** opens a PEM or DER file and shows what is in it
  before anything is trusted. A file that holds several certificates, a
  certificate that isn't a CA, one that has expired, or one already
  trusted or distrusted is shown with the reason and can't be added.
  Otherwise give it a name and choose its purposes, then **Add
  Certificate**.
- **Distrusted** lists what is refused, with the reason it was given, and
  names each certificate where this machine has a copy. **Trust Again…**
  restores one after asking. **Distrust by Fingerprint…** refuses a
  certificate the machine doesn't have, by its whole fingerprint, or by a
  prefix of one it does.
- **Settings** shows whether trustd is up to date, with **Reload** for
  those trustd lets reload it; turns the [files under
  /etc/ssl](~peios/trust/the-compat-files) on and off; and opens the
  permissions editor on `Machine\System\Trust` (**Changing Trust**) and on
  trustd's `ControlSecurity` (**Trust Service**).

The window follows trustd, so a change made elsewhere, with `trust` or
`reg`, appears in it within a few seconds. What you may not change is
shown read-only, with the reason said once.

## Trusting a certificate authority

An internal CA, a test CA, a partner's CA:

```
$ trust add corp-ca /path/to/corp-root.pem
added corp-ca
  CN=Corp Issuing CA,O=Example Ltd,C=GB
  SHA-256 4f2a…c19b
```

The name is yours to choose — it names the *decision*, not the
certificate, so `corp-ca` is a better name than `4f2a`. PEM or DER is
accepted; a file holding more than one certificate is refused, because a
bundle added under one name would be one decision covering several
authorities.

The certificate is checked before it is written: it must parse, it must be
a CA (`basicConstraints`), and it must not have expired. trustd checks it
again when it reads it — it never trusts the writer — but doing it here
means a mistake is a message rather than a line in a log.

To withdraw this named addition:

```
$ trust remove corp-ca
```

### Purposes

By default an addition is trusted for `ServerAuth` — validating a TLS
server. Say otherwise if you mean otherwise:

```
$ trust add corp-ca corp-root.pem --purposes ServerAuth,CodeSigning
```

The purpose is recorded with the addition and can filter socket queries.
Do not assume it limits the compatibility files. The inspected
[trustd 0.1.6 renderer](https://github.com/peios/trustd/blob/2fd7d86aac00e207320bda1ae11045aec3d61fbf/trustd/src/render.rs#L95-L108)
writes every composed root to both PEM bundles and to the
[hashed directory](https://github.com/peios/trustd/blob/2fd7d86aac00e207320bda1ae11045aec3d61fbf/trustd/src/render.rs#L158-L186),
including an addition whose purposes omit `ServerAuth`. This differs from
the [intended ServerAuth-only rendering](https://github.com/peios/trustd/blob/2fd7d86aac00e207320bda1ae11045aec3d61fbf/trustd/src/store.rs#L65-L68)
described in the source.

**Do not use a non-ServerAuth purpose as an isolation boundary for a
machine-wide addition on that implementation.** The certificate's DER is
preserved; this finding does not establish whether a particular TLS
consumer accepts it, which also depends on the certificate and that
consumer's validation rules. This is source inspection, not a live TLS
test or a claim about every installed version.

## Distrusting a certificate authority

This is the one that has to work in a hurry, and it works on any
certificate — one Mozilla shipped or one somebody added:

```
$ trust distrust 018e13f0772532cf --reason "withdrawn, see CA/B incident 2026-08"
distrusted 018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05
  was: CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US
```

After trustd observes the decision and successfully composes and renders
the new set, the root is absent from its socket set, the rendered bundles
and the hashed directory. **Withdrawal does not require a package
update.** Check the result below: a composition failure retains the old
set, while a rendering failure can leave the socket and files different.
Neither a registry write nor socket readback proves that every running
application has stopped using a cached copy.

A certificate is named by its SHA-256 fingerprint — never by subject name,
which is forgeable and reused. Any of these work:

```
018e13f0772532cf                      the prefix `trust list` prints
018E13F0…C1B05                        upper case
01:8e:13:f0:…                          colon-separated, as other tools print it
/path/to/the-certificate.pem          the file itself
```

Distrusting a certificate this machine does not have is legitimate and is
recorded rather than refused — the entry sits there, and if that root ever
arrives in a bundle upgrade or an addition, it is already refused.

To see what has been decided, and to undo it:

```
$ trust list --distrusted
018e13f0772532cf  withdrawn, see CA/B incident 2026-08

1 distrusted

$ trust restore 018e13f0772532cf
restored 018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05
```

## Verify the change

A successful write records a decision. Check that trustd has applied it:

1. Run `trust status`. If health is `degraded`, follow [the recovery steps
   below](#when-the-store-is-degraded). If entries were skipped, read the
   warnings in trustd's log; a skipped entry does not establish trust.
2. Run `trust list` to inspect the effective set. For an addition, use
   `trust show <fingerprint>` to check its full fingerprint, source and
   purposes. `trust list --purpose ServerAuth` filters the socket reply;
   it does not inventory or constrain the compatibility files. See the
   [purpose limitation](#purposes).
3. For a distrust, check that the certificate is absent from `trust list`
   and that the decision appears in `trust list --distrusted`. The latter
   reads the registry, so it is not enough on its own. After `trust restore`,
   check the effective set again: removing a distrust does not supply a
   certificate that is no longer shipped or added.

Retest the affected application. Programs with private trust stores use
their own policy; a successful `trust` command is not an application TLS
test.

## Doing it from the registry

`trust` writes registry values and nothing else, so `reg` does the same job
and is subject to exactly the same access check:

```
Machine\System\Trust\Certificates\
  Add\<name>\
    Certificate   REG_BINARY    the certificate, DER
    Purposes      REG_MULTI_SZ  default ServerAuth
  Distrust\
    <fingerprint> REG_SZ        why, for whoever reads it later
```

Write `Certificate` **last** when creating an entry by hand. Until it
exists the entry is incomplete, and trustd deliberately skips incomplete
entries rather than acting on half of one.

This is also how a domain distributes trust: pushing a value to
`Trust\Certificates\Add` on every member is an ordinary policy write, not
a special mechanism.

## Packages may offer trust, never take it

A package must never widen what the whole machine trusts by being
installed — `peipkg install` quietly adding a CA is a supply-chain hole,
and every system that allowed it eventually closed it.

A package that comes with a CA ships a *seed* (`/usr/share/regim/…`),
inert until an image names it in `[registry] autoapply` or an
administrator applies it. Installing the package grants nothing.

A package shipping a trust store for **its own** private use — a browser,
a language runtime — is unaffected by any of this. Those are ordinary
files that only that program reads.

## When the store is degraded

```
$ trust status
health       degraded — cannot read /usr/share/ca-certificates/mozilla.crt: …
```

`degraded` can report either a composition failure or a rendering failure.
They need different readback. In the inspected
[trustd 0.1.6 refresh path](https://github.com/peios/trustd/blob/2fd7d86aac00e207320bda1ae11045aec3d61fbf/trustd/src/main.rs#L103-L202),
a composition failure leaves the previous set and files untouched. A
rendering failure happens after the socket set has changed; it can leave
old, new or missing compatibility artifacts. Do not assume all consumers
still use one last-good store.

Use the error in `trust status` to choose the next step:

- For a missing or damaged bundle, [check the installed
  package](~peios/package-management/inspecting-and-verifying#verifying-installed-files)
  and repair the package problem. Do not edit the generated `/etc/ssl` files.
- For a distrust list that would empty the store, review
  `trust list --distrusted` and correct unintended decisions. Do not restore
  an intentionally distrusted CA just to clear the health warning.
- For `render failed`, preserve the operation and path in the error and
  investigate that filesystem failure. Compare the socket set with the
  files the affected program actually uses; the `rendered` paths can be
  retained from the last successful render and are not a fresh file
  inventory after failure. Do not hand-edit the generated files or assume
  a successful `trust list` proves they were updated. See [compatibility
  rendering limits](~peios/trust/the-compat-files).

Once the cause is fixed, ask trustd to recompose:

```
$ trust reload
```

Reload requires permission to control trustd; Security Policy exposes its
`ControlSecurity` permissions under **Settings → Trust Service**. If reload
is refused, have an authorized administrator perform it.

The inspected daemon replies successfully to an authorized `trust reload`
even if recomposition or rendering failed. Run `trust status` again and
confirm `health` is `ok`, then [verify the intended
change](#verify-the-change) and retest the affected application. Until
recovery succeeds, do not assume a newly recorded addition or distrust is
in force for every consumer.

Skipped entries are different and are not a degraded state: `trust status`
counts them and the log names each one. Correct the named entry, then check
the effective set again.
