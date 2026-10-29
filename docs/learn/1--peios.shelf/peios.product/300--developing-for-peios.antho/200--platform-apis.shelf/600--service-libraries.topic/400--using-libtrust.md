---
title: Using libtrust
type: reference
description: Operations, ownership, errors, and Rust access for libtrust ABI 1.
---

`libtrust.so.1` provides the public C interface for trustd. The
`trust-client` crate wraps the same shared library and returns owned Rust
values. Internal implementation crates do not replace this public boundary.

## Operations

The library reads status and complete root snapshots, subscribes to changes,
and requests recomposition. Snapshot chunks must belong to one generation;
the library rejects incomplete or mixed-generation results.

Certificate helpers decode, inspect, and vet candidate roots. Decoding or
inspecting a certificate does not make it trusted. Other helpers need no
daemon: they compute a certificate's SHA-256 fingerprint, convert between
DER and PEM, normalize a fingerprint as typed, and resolve a whole
fingerprint or an unambiguous prefix of at least eight digits against a
list of fingerprints. `peios_trust_default_control_security()` returns the
descriptor trustd checks against when the `ControlSecurity` value is
absent. Management operations add
or remove registry entries, record or remove distrust, and configure
compatibility output using the caller's own rights. An access probe is not
an authority token: the actual operation can still fail.

Registry writes and daemon recomposition are separate operations. Request a
reload after management changes when immediate recomposition is required,
and handle either operation's error. A failed reload does not roll back a
completed registry write.

## Linking and ownership

Include `<peios/trust.h>` and use the `trust` pkg-config module. The
installed header and `libtrust(3)` describe individual functions and data
layouts. `peios_trust_abi_version()` returns the ABI major version, 1.

Each operation returns an owned result, including failures. Check
`peios_trust_result_error()` before reading a view, and release the result
exactly once with `peios_trust_result_free()`. Error codes are POSIX numbers;
human-readable diagnostic wording is not a stable identifier. Reading the
stored error does not set thread-local `errno`.

`peios_trust_result_failure()` gives the kind of failure, which is also
stable:

| Constant | Failure |
|---|---|
| `PEIOS_TRUST_FAILURE_NONE` | The operation succeeded |
| `PEIOS_TRUST_FAILURE_OTHER` | Any other failure, such as an unreachable daemon or an ambiguous prefix |
| `PEIOS_TRUST_FAILURE_DENIED` | The caller's rights refused the change |
| `PEIOS_TRUST_FAILURE_NOT_FOUND` | No such root, addition, distrust entry, or matching fingerprint |
| `PEIOS_TRUST_FAILURE_MALFORMED` | The bytes are not a certificate |
| `PEIOS_TRUST_FAILURE_NOT_A_CA` | The certificate is not a certificate authority's |
| `PEIOS_TRUST_FAILURE_EXPIRED` | The certificate has expired |
| `PEIOS_TRUST_FAILURE_NO_CERTIFICATE` | PEM text holds no certificate block |

Strings are UTF-8 spans with explicit byte lengths, without terminating NUL
bytes. Input spans are borrowed for the call and must remain live, aligned,
and initialized. A null pointer with zero length represents absent optional
text; a non-null pointer with zero length represents present empty text.
Returned strings, arrays, and nested views belong to the result. Copy what
you need before freeing it. Handles from another library are not valid here.

## Connections and failure

Each ordinary daemon operation opens its own filesystem Unix socket. The
system default is `/run/trustd/trust.sock`; clients can select another socket
for a
private service instance or a test.

A positive timeout in milliseconds bounds connection, sending, and receiving
together. A full connection queue can fail immediately. A transport error
does not establish whether a requested change was applied. The library does
not automatically replay operations after an uncertain failure.

## Rust access

Use `Client::system(Duration)` for the installed daemon or
`Client::new(path, Duration)` for an explicit socket. The wrapper copies
result views into Rust values and releases C results through `Drop`. Its
`Error` carries the POSIX `code`, the failure's `kind` as an `ErrorKind`,
and the diagnostic `message`. The crate also exports the registry key and
value names trustd reads, and the certificate `Details` and `Parsed` types.
Select a matching source revision of `trust-client` and link the installed
shared library; the crate is not a precompiled Rust ABI package.

## Subscriptions

A subscription is owned separately from each returned snapshot. Calls and
freeing on one subscription must not overlap. A receive timeout retains
partial framing so a later call can continue. Other transport or protocol
errors close the stream; create a new subscription explicitly if needed.
The Rust wrapper requires mutable access to receive the next snapshot.
