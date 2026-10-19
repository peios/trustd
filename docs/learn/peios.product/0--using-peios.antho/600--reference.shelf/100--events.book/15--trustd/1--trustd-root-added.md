---
title: "trustd.root.added"
description: "A root certificate authority entered the set this machine trusts."
---

- **Event type:** `trustd.root.added`
- **Defined in:** `trustd.evman`
- **Tier:** standard
- **Gating:** none — every root that enters the set in force is recorded
- **Cardinality:** one per root that entered the set

A root certificate authority entered the set this machine trusts. trustd
recomposes the set whenever the registry's additions or distrusts change,
or the shipped bundle is replaced, and writes one record for each root that
is in the new set and was not in the one before: an addition, a distrust
lifted, or a root a bundle upgrade brought in.

The set trustd composes when it starts is the baseline these records count
from, and is not recorded. A change made while trustd was not running is
seen only as part of that baseline.

No subject identity is recorded. trustd observes a changed set, not the
identity that wrote policy or installed the bundle. Correlate the event with
registry audit records under `Machine\System\Trust\Certificates` or the
package update records when identifying the initiating operation.

## Fields

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `object.certificate.digest` | `bin` | required | The SHA-256 digest of the certificate's DER encoding: its fingerprint, the name a distrust gives it and the one `trust list` prints, carried as 32 bytes rather than as hexadecimal. |
| `object.certificate.name` | `str` | required | The certificate's subject distinguished name, in the form `trust show` prints it, such as `CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US`. |
| `object.certificate.purposes` | `str.enum[]` | required | The purposes the root is trusted for now. |

The event envelope supplies metadata separately from these payload fields.
See [Reading Stored
Records](~peios/reading-records/stored-records)
for inspecting the records held by eventd.

The corresponding event entry in `trustd.evman` owns this definition.
