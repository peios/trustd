//! Composition under arbitrary input: a bundle of arbitrary text, arbitrary
//! additions, arbitrary distrusts.
//!
//! The invariants are the ones that keep a machine's trust honest:
//! composition either succeeds or leaves the caller to keep what it had; a
//! distrusted fingerprint is never in the result; and the result is
//! deterministic, so an unchanged store never rewrites a file.
#![no_main]
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use trustd::store::{self, Addition};

const REAL: &str = include_str!("../../trustd/tests/fixtures/comodo-ecc.pem");
const REAL2: &str = include_str!("../../trustd/tests/fixtures/netlock-arany.pem");

#[derive(Arbitrary, Debug)]
struct Input {
    bundle_extra: Vec<u8>,
    real_copies: u8,
    additions: Vec<(String, Vec<u8>)>,
    distrust: Vec<String>,
    now: Option<i64>,
}

fuzz_target!(|input: Input| {
    let mut bundle = String::new();
    for _ in 0..input.real_copies % 80 {
        bundle.push_str(REAL);
        bundle.push_str(REAL2);
    }
    if let Ok(text) = std::str::from_utf8(&input.bundle_extra) {
        bundle.push_str(text);
    }
    let additions: Vec<Addition> = input
        .additions
        .into_iter()
        .take(16)
        .map(|(name, der)| Addition { name, der, purposes: vec![] })
        .collect();

    let Ok(composed) = store::compose(&bundle, &additions, &input.distrust, input.now) else {
        return;
    };
    // A successful composition is never empty, and never contains anything
    // that was distrusted.
    assert!(!composed.roots.is_empty());
    let distrust: Vec<String> = input.distrust.iter().map(|f| store::normalise_fingerprint(f)).collect();
    for root in &composed.roots {
        assert!(!distrust.contains(&root.parsed.fingerprint), "a distrusted root survived");
    }
    // Deterministic, so an unchanged store rewrites nothing.
    let again = store::compose(&bundle, &additions, &input.distrust, input.now).unwrap();
    assert_eq!(
        composed.roots.iter().map(|r| &r.parsed.fingerprint).collect::<Vec<_>>(),
        again.roots.iter().map(|r| &r.parsed.fingerprint).collect::<Vec<_>>()
    );
    // No duplicates: a bundle repeated many times is still one store.
    let mut seen: Vec<&String> = composed.roots.iter().map(|r| &r.parsed.fingerprint).collect();
    let before = seen.len();
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), before, "the store holds a duplicate");
});
