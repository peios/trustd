---
title: The files under /etc/ssl
type: concept
description: Why the trust store is rendered to files at all, what each of the three artifacts is for, and what turning them off does.
related:
  - peios/trust/overview
  - peios/linux-compatibility/name-service-switch
---

The machine's trust store is a socket. The files under `/etc/ssl` are a
compatibility rendering of it, for software that reads trust from a path —
which today is very nearly all software.

They are generated. A manual edit lasts only until the next change, and a
header at the top of the bundle says so. Use [adding and
distrusting](~peios/trust/adding-and-distrusting) to change trust policy.
Use `trust status` to check whether these files are enabled and where they
were rendered.

## Three artifacts, because the ecosystem does not agree

| Path | Who reads it |
|---|---|
| `/etc/ssl/certs/ca-certificates.crt` | Go probes this first; most software is configured with it |
| `/etc/ssl/cert.pem` | OpenSSL's default `CAfile` on this system |
| `/etc/ssl/certs/<subject-hash>.0` | OpenSSL's default `CApath` |

The hashed directory is not decoration. OpenSSL looks a certificate up
there by a hash of its subject, so updating a PEM bundle alone does not
withdraw a root from that lookup path. Roots whose subject hashes collide
use successive suffixes, `.0`, `.1` and so on.

The inspected [trustd 0.1.6 renderer](https://github.com/peios/trustd/blob/2fd7d86aac00e207320bda1ae11045aec3d61fbf/trustd/src/render.rs#L158-L200)
builds a new `certs` directory, installs it, and then replaces `cert.pem`
separately. It first tries an atomic directory exchange. Its
[fallback path](https://github.com/peios/trustd/blob/2fd7d86aac00e207320bda1ae11045aec3d61fbf/trustd/src/render.rs#L246-L286)
uses separate renames, which can temporarily leave `certs` absent; failure
after the first rename can leave it absent until repaired. There is no
single atomic switch covering the socket and all three file paths.

A rendering error can occur after some artifacts changed, and the socket
set is updated before rendering starts. Follow [degraded-store
diagnosis](~peios/trust/adding-and-distrusting#when-the-store-is-degraded)
rather than assuming a last-good store everywhere. These are pinned source
limits, not live filesystem or installed-image verification. Also see the
[purpose-filtering limitation](~peios/trust/adding-and-distrusting#purposes):
that renderer includes all composed roots, regardless of their recorded
purposes.

## Turning them off

`Machine\System\Trust GenerateLinuxTrustFiles` requests the compatibility
mode. These effects require successful rendering or removal:

| Value | Effect |
|---|---|
| `1` (default) | Rendered and kept current. |
| `0` | No files. Programs that read a path find nothing and fail with certificate errors. |
| `2` | Reserved. Treated as `1`. |

`0` is the machine whose entire software set asks the socket — an
appliance image, in practice, where you know what is installed. On a
general-purpose system it breaks curl, Python, Go binaries and anything
else that reads a bundle, and the breakage looks like a certificate
problem rather than a configuration one, so set it deliberately.

Switching to `0` asks trustd to remove the rendered files. Successful
removal leaves the directory itself empty. The inspected renderer removes
`cert.pem` and then the contents of `certs` in separate operations; a
failure can leave some files behind. Check health and the actual paths
before treating compatibility trust as disabled. A saved `0` or a socket
reply alone does not prove removal succeeded.

```
$ reg set Machine/System/Trust GenerateLinuxTrustFiles dword:0
$ trust status
compat       GenerateLinuxTrustFiles = 0 (no files; the socket is the only store)
```

The socket keeps serving throughout — `trust list` still answers, and so
does any program that speaks to trustd directly.

In Security Policy, the **Certificate Files** switch under **Settings**
writes the same value. Turning it off asks first because programs that
rely on these paths can lose their trust store. Allow trustd to apply the
change, then verify health and the affected application.

To restore compatibility files after disabling them:

```
$ reg set Machine/System/Trust GenerateLinuxTrustFiles dword:1
$ trust status
```

Confirm `GenerateLinuxTrustFiles = 1`, the rendered paths, and `health` of
`ok`, then retry the affected program. If the store is degraded, follow
[the recovery steps](~peios/trust/adding-and-distrusting#when-the-store-is-degraded)
before relying on the rendered trust.

## Why a copy, when name resolution gets a pointer

`/etc/resolv.conf` on Peios is a constant file naming the resolver, and
nothing is ever generated into it. Trust cannot work that way: there is no
"ask over here" a certificate bundle can express. A file that lists
authorities has to *be* the list.

That is the whole difference between the two, and the reason this one
carries a knob and a warning while the other does not.

> [!NOTE]
> The rendered files come out readable by everyone, which is correct — the
> set of certificate authorities a machine trusts is not a secret, and
> every program on the machine needs it. What is protected is *changing*
> it, which is a registry write.
