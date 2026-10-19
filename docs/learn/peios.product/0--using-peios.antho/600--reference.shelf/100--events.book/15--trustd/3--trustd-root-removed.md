---
title: "trustd.root.removed"
description: "A root certificate authority left the set this machine trusts, and no distrust names it: its addition was withdrawn, or a bundle upgrade dropped it."
---

- **Event type:** `trustd.root.removed`
- **Defined in:** `trustd.evman`
- **Tier:** standard
- **Gating:** none — every root that leaves the set in force, other than by
  distrust, is recorded
- **Cardinality:** one per root that left the set

A root certificate authority left the set this machine trusts, and no
distrust names it: its addition was withdrawn, or a bundle upgrade dropped
it. A root that leaves because it was distrusted is
`trustd.root.distrusted` instead.

No subject, as for `trustd.root.added`.

## Fields

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `object.certificate.digest` | `bin` | required | The SHA-256 digest of the certificate's DER encoding: its fingerprint, the name a distrust gives it and the one `trust list` prints, carried as 32 bytes rather than as hexadecimal. |
| `object.certificate.name` | `str` | required | The certificate's subject distinguished name, in the form `trust show` prints it, such as `CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US`. |
| `object.certificate.purposes` | `str.enum[]` | required | The purposes the root was trusted for until it left. |

The event envelope supplies metadata separately from these payload fields.
See [Reading Stored
Records](~peios/reading-records/stored-records)
for inspecting the records held by eventd.

The corresponding event entry in `trustd.evman` owns this definition.
