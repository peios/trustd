//! The certificate parser, on arbitrary bytes.
//!
//! It reads whatever an administrator wrote into the registry and whatever
//! the shipped bundle holds. Nothing may panic, and a certificate that
//! parses must have a usable identity — a store that hands out a
//! fingerprint it cannot reproduce would name the wrong certificate in a
//! distrust.
#![no_main]
use libfuzzer_sys::fuzz_target;
use trustd::cert;

fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = cert::parse(data, None) {
        assert_eq!(parsed.fingerprint.len(), 64);
        assert!(parsed.fingerprint.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        assert_eq!(parsed.subject_hash.len(), 8);
        assert!(parsed.subject_hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(parsed.der, data);
        // The identity must be reproducible: re-parsing our own PEM
        // rendering yields the same certificate.
        let pem = cert::to_pem(&parsed.der);
        let again = cert::from_pem(&pem);
        assert_eq!(again.len(), 1);
        assert_eq!(again[0], parsed.der);
        let reparsed = cert::parse(&again[0], None).expect("our own rendering parses");
        assert_eq!(reparsed.fingerprint, parsed.fingerprint);
        assert_eq!(reparsed.subject_hash, parsed.subject_hash);
    }
    // The PEM reader takes arbitrary text and must never panic either.
    if let Ok(text) = std::str::from_utf8(data) {
        for der in cert::from_pem(text) {
            let _ = cert::parse(&der, Some(0));
        }
    }
});
