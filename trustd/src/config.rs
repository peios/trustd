//! `Machine\System\Trust`: what the registry says this machine trusts.
//!
//! The registry holds *decisions*, never vendor payload. The Mozilla roots
//! are package data on disk; what lives here is what somebody chose — an
//! addition, a distrust, the compat mode, the control object's descriptor.
//! That is what keeps a domain audit and a `reg` diff legible: every row is
//! an act, not a hundred and fifty rows of upstream churn.
//!
//! ```text
//! Machine\System\Trust
//!   ControlSecurity          REG_BINARY  the control object's descriptor
//!   GenerateLinuxTrustFiles  REG_DWORD   0 none, 1 rendered, 2 reserved
//!   Certificates\
//!     Add\<name>\
//!       Certificate          REG_BINARY  the certificate, DER
//!       Purposes             REG_MULTI_SZ  default ServerAuth
//!     Distrust\
//!       <sha256 fingerprint> REG_SZ      why, for whoever reads it later
//! ```

use libtrust::{
    ADD_KEY, CERTIFICATE_VALUE, COMPAT_VALUE, CONTROL_SECURITY_VALUE, DISTRUST_KEY, PURPOSES_VALUE,
    TRUST_KEY,
};
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};

use crate::log;
use crate::render::Compat;
use crate::store::{Addition, normalise_fingerprint};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub additions: Vec<Addition>,
    /// Normalised lowercase hex fingerprints.
    pub distrust: Vec<String>,
    pub compat: Compat,
    pub control_security: Option<Vec<u8>>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            additions: Vec::new(),
            distrust: Vec::new(),
            compat: Compat::Files,
            control_security: None,
        }
    }
}

fn sz(v: &RegValue) -> Option<String> {
    if v.ty != ValueType::SZ && v.ty != ValueType::EXPAND_SZ {
        return None;
    }
    let end = v.data.iter().position(|&b| b == 0).unwrap_or(v.data.len());
    String::from_utf8(v.data[..end].to_vec()).ok()
}

fn multi(v: &RegValue) -> Option<Vec<String>> {
    match v.ty {
        ValueType::MULTI_SZ => Some(
            v.data
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| String::from_utf8(s.to_vec()).ok())
                .collect(),
        ),
        ValueType::SZ | ValueType::EXPAND_SZ => sz(v).map(|s| vec![s]),
        _ => None,
    }
}

fn read(key: &Key, name: &str) -> Option<RegValue> {
    key.query_value(name.as_bytes(), None).ok()
}

fn open(parent: Option<&Key>, path: &str) -> Option<Key> {
    Key::open(
        parent,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    )
    .ok()
}

pub fn load() -> Config {
    let mut config = Config::default();
    let Some(root) = open(None, TRUST_KEY) else {
        // Before the seed applies there is no key, and the defaults are the
        // right answer: render the shipped roots, add nothing, distrust
        // nothing.
        return config;
    };
    if let Some(v) = read(&root, COMPAT_VALUE) {
        if v.ty == ValueType::DWORD && v.data.len() == 4 {
            config.compat = Compat::from_dword(u32::from_le_bytes([
                v.data[0], v.data[1], v.data[2], v.data[3],
            ]));
        }
    }
    config.control_security = read(&root, CONTROL_SECURITY_VALUE)
        .filter(|v| v.ty == ValueType::BINARY && !v.data.is_empty())
        .map(|v| v.data);

    let Some(certificates) = open(Some(&root), "Certificates") else {
        return config;
    };

    if let Some(add) = open(Some(&certificates), ADD_KEY) {
        for subkey in add.subkeys(None) {
            let Ok(subkey) = subkey else { continue };
            let Ok(name) = String::from_utf8(subkey.name.clone()) else {
                continue;
            };
            let Some(entry) = open(Some(&add), &name) else {
                continue;
            };
            let Some(certificate) = read(&entry, CERTIFICATE_VALUE) else {
                // A key with no certificate is an entry mid-write (the
                // certificate is written last, exactly so this state is
                // never mistaken for a valid one) or an abandoned one.
                continue;
            };
            if certificate.ty != ValueType::BINARY || certificate.data.is_empty() {
                log::warn(format_args!(
                    "Add\\{name}: {CERTIFICATE_VALUE} is not a non-empty REG_BINARY; ignored"
                ));
                continue;
            }
            let purposes = read(&entry, PURPOSES_VALUE)
                .and_then(|v| multi(&v))
                .unwrap_or_default();
            config.additions.push(Addition {
                name,
                der: certificate.data,
                purposes,
            });
        }
    }

    if let Some(distrust) = open(Some(&certificates), DISTRUST_KEY) {
        for value in distrust.values(None) {
            let Ok(value) = value else { continue };
            let Ok(name) = String::from_utf8(value.name.clone()) else {
                continue;
            };
            let fingerprint = normalise_fingerprint(&name);
            if fingerprint.len() != 64 || !fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) {
                log::warn(format_args!(
                    "Distrust\\{name}: not a SHA-256 fingerprint (64 hex digits); ignored — a distrust that matches nothing is worse than an error"
                ));
                continue;
            }
            config.distrust.push(fingerprint);
        }
    }

    config.additions.sort_by(|a, b| a.name.cmp(&b.name));
    config.distrust.sort();
    config.distrust.dedup();
    config
}

/// Arm a subtree watch on `Machine\System\Trust`.
///
/// The seed creates the key, so it exists before trustd starts and there is
/// no "watch the parent until it appears" dance. If it is somehow absent,
/// the caller falls back to re-arming later.
pub fn watch() -> peios::Result<Key> {
    use peios::registry::NotifyFilter;
    let key = Key::open(None, TRUST_KEY, KeyAccess::NOTIFY, OpenFlags::empty())?;
    key.notify(NotifyFilter::ALL, true)?;
    key.set_nonblocking(true)?;
    Ok(key)
}
