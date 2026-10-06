//! The records trustd writes: `trustd.root.added`, `.removed` and
//! `.distrusted` (`trustd.evman`).
//!
//! trustd sees a change to the trust store only as the difference between
//! two compositions, so that is what it records: one event per root that
//! entered or left the effective set. Who made the change is not trustd's
//! to say. A registry addition or distrust is a registry write, which LCS
//! audits; a bundle that changed underneath it is a package operation,
//! which peipkg records. So these events carry no subject.
//!
//! The first composition after trustd starts is the baseline, not a change:
//! recording it would write one `added` per shipped root at every boot.
//!
//! The types are `standard` (PGSS §6.8), so each is written only if the
//! emission policy leaves it on. Writing needs `SeAuditPrivilege`, which
//! `trustd-service.reg` grants to trustd's service SID.

use std::collections::HashSet;

use peios::event::{EventPolicy, Tier};
use peios::msgpack::Writer;
use sha2::{Digest, Sha256};

use crate::log;
use crate::store::{self, Entry};

/// How a root's place in the effective set changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// It is in the set and was not before.
    Added,
    /// It left the set, and no distrust names it.
    Removed,
    /// It left the set because a distrust names it.
    Distrusted,
}

impl Change {
    pub fn event_type(self) -> &'static str {
        match self {
            Change::Added => "trustd.root.added",
            Change::Removed => "trustd.root.removed",
            Change::Distrusted => "trustd.root.distrusted",
        }
    }
}

/// Every root whose place in the set differs between `old` and `new`, with
/// the entry that describes it: the new one for an addition, the old one
/// for a root that left. `distrust` is the distrust list the new set was
/// composed under, as written in the registry.
///
/// Additions come first, then departures, each in fingerprint order (the
/// order a composition keeps its roots in).
pub fn changes<'a>(
    old: &'a [Entry],
    new: &'a [Entry],
    distrust: &[String],
) -> Vec<(Change, &'a Entry)> {
    let before: HashSet<&str> = old.iter().map(|e| e.parsed.fingerprint.as_str()).collect();
    let after: HashSet<&str> = new.iter().map(|e| e.parsed.fingerprint.as_str()).collect();
    let distrusted: HashSet<String> = distrust
        .iter()
        .map(|f| store::normalise_fingerprint(f))
        .collect();
    let mut out = Vec::new();
    for entry in new {
        if !before.contains(entry.parsed.fingerprint.as_str()) {
            out.push((Change::Added, entry));
        }
    }
    for entry in old {
        if !after.contains(entry.parsed.fingerprint.as_str()) {
            let change = if distrusted.contains(&entry.parsed.fingerprint) {
                Change::Distrusted
            } else {
                Change::Removed
            };
            out.push((change, entry));
        }
    }
    out
}

/// A purpose as the registry spells it (`ServerAuth`), as the enumeration
/// value the record carries (`server-auth`): kebab-case, a hyphen at each
/// lower-to-upper boundary and in place of anything not a letter or digit.
/// `None` for a purpose with no letters or digits at all.
pub fn purpose_value(purpose: &str) -> Option<String> {
    let mut out = String::with_capacity(purpose.len() + 4);
    let mut previous_lower = false;
    let mut pending_hyphen = false;
    for c in purpose.chars() {
        if c.is_ascii_alphanumeric() {
            if (pending_hyphen || (previous_lower && c.is_ascii_uppercase())) && !out.is_empty() {
                out.push('-');
            }
            pending_hyphen = false;
            previous_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
            out.push(c.to_ascii_lowercase());
        } else {
            pending_hyphen = true;
            previous_lower = false;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// The payload every root record carries: the certificate's SHA-256 digest,
/// its subject name and its purposes.
pub fn root_payload(entry: &Entry) -> peios::Result<Vec<u8>> {
    let digest = Sha256::digest(&entry.parsed.der);
    // trustd matches purposes without regard to case, so two spellings of
    // one are one purpose; the first spelling decides the value.
    let mut seen: Vec<String> = Vec::new();
    let mut purposes: Vec<String> = Vec::new();
    for p in &entry.purposes {
        let folded = p.to_ascii_lowercase();
        if seen.contains(&folded) {
            continue;
        }
        seen.push(folded);
        if let Some(v) = purpose_value(p)
            && !purposes.contains(&v)
        {
            purposes.push(v);
        }
    }
    let mut w = Writer::new();
    w.write_map(1)
        .write_str("object")
        .write_map(1)
        .write_str("certificate")
        .write_map(3)
        .write_str("digest")
        .write_bin(&digest)
        .write_str("name")
        .write_str(&entry.parsed.subject)
        .write_str("purposes")
        .write_array(purposes.len() as u32);
    for p in &purposes {
        w.write_str(p);
    }
    w.to_bytes()
}

/// Write one record per change, as the policy allows. Failures are logged:
/// the store has already changed.
pub fn record(policy: Option<&EventPolicy>, changes: &[(Change, &Entry)]) {
    for (change, entry) in changes {
        let event_type = change.event_type();
        // No policy view (it failed to open for want of memory) decides by
        // tier, and standard is on. The payload is built only for a type
        // that is on.
        let enabled = policy.map_or(Ok(true), |p| p.enabled(event_type, Tier::Standard));
        let result = enabled.and_then(|on| {
            if on {
                root_payload(entry).and_then(|p| peios::event::emit(event_type, &p))
            } else {
                Ok(())
            }
        });
        if let Err(e) = result {
            log::warn(format_args!(
                "could not record {event_type} for {}: {e}",
                entry.parsed.subject
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert;
    use crate::store::{Addition, MINIMUM_SHIPPED, compose};
    use libtrust::Source;
    use peios::msgpack::{Reader, Type};
    use std::collections::BTreeMap;

    const COMODO: &str = include_str!("../tests/fixtures/comodo-ecc.pem");
    const NETLOCK: &str = include_str!("../tests/fixtures/netlock-arany.pem");
    const MICROSEC: &str = include_str!("../tests/fixtures/microsec-2009.pem");

    fn bundle(parts: &[&str]) -> String {
        let mut text = String::new();
        for _ in 0..MINIMUM_SHIPPED {
            for part in parts {
                text.push_str(part);
            }
        }
        text
    }

    fn der_of(pem: &str) -> Vec<u8> {
        cert::from_pem(pem).remove(0)
    }

    fn fingerprint_of(pem: &str) -> String {
        cert::fingerprint(&der_of(pem))
    }

    fn kinds(changes: &[(Change, &Entry)]) -> Vec<(Change, String)> {
        changes
            .iter()
            .map(|(c, e)| (*c, e.parsed.fingerprint.clone()))
            .collect()
    }

    #[test]
    fn an_unchanged_store_records_nothing() {
        let a = compose(&bundle(&[COMODO, NETLOCK]), &[], &[], None).unwrap();
        let b = compose(&bundle(&[NETLOCK, COMODO]), &[], &[], None).unwrap();
        assert!(changes(&a.roots, &b.roots, &[]).is_empty());
    }

    #[test]
    fn an_addition_is_added_and_its_withdrawal_is_removed() {
        let shipped = bundle(&[COMODO, NETLOCK]);
        let before = compose(&shipped, &[], &[], None).unwrap();
        let addition = Addition {
            name: "corp-ca".into(),
            der: der_of(MICROSEC),
            purposes: vec!["ServerAuth".into(), "CodeSigning".into()],
        };
        let after = compose(&shipped, &[addition], &[], None).unwrap();
        let found = changes(&before.roots, &after.roots, &[]);
        assert_eq!(
            kinds(&found),
            vec![(Change::Added, fingerprint_of(MICROSEC))]
        );
        assert_eq!(found[0].1.source, Source::Added);
        // Taking it out again is a removal, not a distrust.
        let found = changes(&after.roots, &before.roots, &[]);
        assert_eq!(
            kinds(&found),
            vec![(Change::Removed, fingerprint_of(MICROSEC))]
        );
    }

    #[test]
    fn a_distrust_is_told_apart_from_a_removal_however_it_is_spelled() {
        let shipped = bundle(&[COMODO, NETLOCK, MICROSEC]);
        let before = compose(&shipped, &[], &[], None).unwrap();
        let pasted = fingerprint_of(NETLOCK).to_uppercase();
        let after = compose(&shipped, &[], &[pasted.clone()], None).unwrap();
        let found = changes(&before.roots, &after.roots, &[pasted.clone()]);
        assert_eq!(
            kinds(&found),
            vec![(Change::Distrusted, fingerprint_of(NETLOCK))]
        );
        // Lifting the distrust brings it back as an addition.
        let found = changes(&after.roots, &before.roots, &[]);
        assert_eq!(
            kinds(&found),
            vec![(Change::Added, fingerprint_of(NETLOCK))]
        );
        // A bundle that drops a root without any distrust is a removal.
        let smaller = compose(&bundle(&[COMODO, MICROSEC]), &[], &[], None).unwrap();
        let found = changes(&before.roots, &smaller.roots, &[]);
        assert_eq!(
            kinds(&found),
            vec![(Change::Removed, fingerprint_of(NETLOCK))]
        );
    }

    #[test]
    fn purposes_become_kebab_case_enumeration_values() {
        assert_eq!(purpose_value("ServerAuth").as_deref(), Some("server-auth"));
        assert_eq!(
            purpose_value("CodeSigning").as_deref(),
            Some("code-signing")
        );
        assert_eq!(purpose_value("serverauth").as_deref(), Some("serverauth"));
        assert_eq!(
            purpose_value("Email Protection").as_deref(),
            Some("email-protection")
        );
        assert_eq!(purpose_value("TLS1Client").as_deref(), Some("tls1-client"));
        assert_eq!(purpose_value("  "), None);
    }

    #[derive(Debug, PartialEq)]
    enum V {
        Map(BTreeMap<String, V>),
        Array(Vec<V>),
        Str(String),
        Bin(Vec<u8>),
    }

    fn decode(r: &mut Reader<'_>) -> V {
        match r.peek().expect("a value") {
            Type::Map => {
                let n = r.read_map().unwrap();
                let mut m = BTreeMap::new();
                for _ in 0..n {
                    let k = r.read_str().unwrap().to_owned();
                    let v = decode(r);
                    assert!(m.insert(k, v).is_none(), "a key is written once");
                }
                V::Map(m)
            }
            Type::Array => {
                let n = r.read_array().unwrap();
                V::Array((0..n).map(|_| decode(r)).collect())
            }
            Type::Str => V::Str(r.read_str().unwrap().to_owned()),
            Type::Bin => V::Bin(r.read_bin().unwrap().to_vec()),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn the_payload_is_the_binary_digest_the_subject_and_the_purposes() {
        let entry = Entry {
            parsed: cert::parse(&der_of(MICROSEC), None).unwrap(),
            source: Source::Added,
            name: Some("corp-ca".into()),
            purposes: vec![
                "ServerAuth".into(),
                "serverauth".into(),
                "CodeSigning".into(),
            ],
        };
        let bytes = root_payload(&entry).unwrap();
        let mut r = Reader::new(&bytes);
        let v = decode(&mut r);
        assert_eq!(r.remaining(), 0);
        let V::Map(top) = &v else { panic!() };
        assert_eq!(top.len(), 1, "no subject, nothing but the certificate");
        let Some(V::Map(object)) = top.get("object") else {
            panic!()
        };
        let Some(V::Map(c)) = object.get("certificate") else {
            panic!()
        };
        let Some(V::Bin(digest)) = c.get("digest") else {
            panic!()
        };
        // The same SHA-256 the fingerprint is, as 32 bytes rather than hex.
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(digest.len(), 32);
        assert_eq!(hex, entry.parsed.fingerprint);
        assert_eq!(c.get("name"), Some(&V::Str(entry.parsed.subject.clone())));
        assert_eq!(
            c.get("purposes"),
            Some(&V::Array(vec![
                V::Str("server-auth".into()),
                V::Str("code-signing".into())
            ])),
            "kebab-case, each once"
        );
    }
}
