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

No subject. PGSS <span>§</span>6.4 asks an event about an action for the principal that
acted, and the action here is not trustd's: trustd only recomposes the set
from what others decided, and it is never told who they were. The
principal that acted is whoever wrote the addition or the distrust, which
the registry records (LCS, where the key is audited), or whoever upgraded
the bundle, which peipkg records. Naming trustd's own SID instead would
answer "who distrusted this root?" with trustd, which is wrong. The writer
is on the registry's record of the write under
`Machine\System\Trust\Certificates`, just before this one.

## Fields

| Field | Type | Presence | Meaning |
|---|---|---|---|
| [`object.certificate.digest`](~peios/events/field-index/fields-object#object.certificate.digest) | `bin` | required | The SHA-256 digest of the certificate's DER encoding: its fingerprint, the name a distrust gives it and the one `trust list` prints, carried as 32 bytes rather than as hexadecimal. |
| [`object.certificate.name`](~peios/events/field-index/fields-object#object.certificate.name) | `str` | required | The certificate's subject distinguished name, in the form `trust show` prints it, such as `CN=DigiCert TLS ECC P384 Root G5,O=DigiCert\, Inc.,C=US`. |
| [`object.certificate.purposes`](~peios/events/field-index/fields-object#object.certificate.purposes) | `str.enum[]` | required | The purposes the root is trusted for now. |

Every record also carries the header fields of [the envelope](~peios/events/introduction/the-envelope), which no payload repeats.

*Generated from `trustd.evman` by `pkm/tools/gen-events-book.py`. Edit the fragment, not this page.*
