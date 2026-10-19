---
title: "trustd.root.distrusted"
description: "A distrust took a root certificate authority out of the set this machine trusts."
---

- **Event type:** `trustd.root.distrusted`
- **Defined in:** `trustd.evman`
- **Tier:** standard
- **Gating:** none — every root a distrust takes out of the set in force is recorded
- **Cardinality:** one per root that left the set

A distrust took a root certificate authority out of the set this machine
trusts. A distrust applies to shipped roots and to additions alike. A
distrust naming a certificate the machine does not have takes nothing out
and writes no record; if that certificate arrives later it is refused, and
never enters the set to leave it.

No subject, as for `trustd.root.added`.

## Fields

| Field | Type | Presence | Meaning |
|---|---|---|---|
| [`object.certificate.digest`](~peios/events/field-index/fields-object#object.certificate.digest) | `bin` | required | The SHA-256 digest of the certificate's DER encoding: its fingerprint, the name a distrust gives it and the one `trust list` prints, carried as 32 bytes rather than as hexadecimal. |
| [`object.certificate.name`](~peios/events/field-index/fields-object#object.certificate.name) | `str` | required | The certificate's subject distinguished name, in the form `trust show` prints it, such as `CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US`. |
| [`object.certificate.purposes`](~peios/events/field-index/fields-object#object.certificate.purposes) | `str.enum[]` | required | The purposes the root was trusted for until it was distrusted. |

Every record also carries the header fields of [the envelope](~peios/events/introduction/the-envelope), which no payload repeats.

*Generated from `trustd.evman` by `pkm/tools/gen-events-book.py`. Edit the fragment, not this page.*
