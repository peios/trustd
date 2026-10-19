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

use std::io;
use peios::registry::{Key, KeyAccess, OpenFlags, ValueType};
#[path = "registry_reader.rs"]
mod reader;
use reader::{Reader, open, strings};
use trust_core::{
    ADD_KEY, CERTIFICATE_VALUE, COMPAT_VALUE, CONTROL_SECURITY_VALUE, DISTRUST_KEY, PURPOSES_VALUE,
    TRUST_KEY,
};

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

pub fn load() -> io::Result<Config> {
    let root = open(None, TRUST_KEY)?;
    load_from(root.as_ref())
}

fn load_from(root: Option<&impl Reader>) -> io::Result<Config> {
    let mut config = Config::default();
    let Some(root) = root else {
        return Ok(config);
    };
    if let Some(v) = root.value(COMPAT_VALUE)?
        && v.ty == ValueType::DWORD
        && v.data.len() == 4
    {
        config.compat = Compat::from_dword(u32::from_le_bytes([
            v.data[0], v.data[1], v.data[2], v.data[3],
        ]));
    }
    config.control_security = root
        .value(CONTROL_SECURITY_VALUE)?
        .filter(|v| v.ty == ValueType::BINARY && !v.data.is_empty())
        .map(|v| v.data);

    let Some(certificates) = root.child("Certificates")? else {
        return Ok(config);
    };

    if let Some(add) = certificates.child(ADD_KEY)? {
        for subkey in add.names()? {
            let name = reader::text(&subkey)?;
            let entry = add
                .child(&name)?
                .ok_or_else(|| reader::invalid("enumerated certificate key disappeared"))?;
            let Some(certificate) = entry.value(CERTIFICATE_VALUE)? else {
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
            let purposes = strings(&entry, PURPOSES_VALUE)?.unwrap_or_default();
            config.additions.push(Addition {
                name,
                der: certificate.data,
                purposes,
            });
        }
    }

    if let Some(distrust) = certificates.child(DISTRUST_KEY)? {
        for value in distrust.values()? {
            let name = reader::text(&value.name)?;
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
    Ok(config)
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

#[cfg(test)]
mod read_tests {
    use super::*;
    struct Fixture {
        fault: &'static str,
        path: String,
    }
    impl Reader for Fixture {
        fn value(&self, name: &str) -> io::Result<Option<peios::registry::RegValue>> {
            if self.fault == "value" && name == "ControlSecurity" {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(None)
        }

        fn values(&self) -> io::Result<Vec<peios::registry::ValueRecord>> {
            if self.fault == "values" {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(vec![])
        }
        fn child(&self, name: &str) -> io::Result<Option<Self>> {
            if self.fault == "child" {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            if self.fault == "disappeared" && name == "entry" {
                return Ok(None);
            }
            Ok(Some(Self {
                fault: self.fault,
                path: name.into(),
            }))
        }

        fn names(&self) -> io::Result<Vec<Vec<u8>>> {
            if self.fault == "names" {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if self.fault == "disappeared" && self.path == "Add" {
                return Ok(vec![b"entry".to_vec()]);
            }
            Ok(vec![])
        }
    }

    #[test]
    fn missing_configuration_keeps_documented_defaults() {
        assert_eq!(load_from(None::<&Fixture>).unwrap(), Config::default());
        assert_eq!(
            load_from(Some(&Fixture {
                fault: "",
                path: String::new()
            }))
            .unwrap(),
            Config::default()
        );
    }
    #[test]
    fn failed_value_reads_do_not_produce_a_partial_configuration() {
        let error = load_from(Some(&Fixture {
            fault: "value",
            path: String::new(),
        }))
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }
    #[test]
    fn malformed_text_cannot_silently_remove_one_list_entry() {
        let value = peios::registry::RegValue {
            sequence: 0,
            ty: ValueType::MULTI_SZ,
            data: b"valid\0\xff\0\0".to_vec(),
            layer: vec![],
        };
        assert_eq!(
            reader::multi(&value).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn unreadable_subtrees_and_enumeration_failures_reject_the_read() {
        for fault in ["child", "values"] {
            assert!(
                load_from(Some(&Fixture {
                    fault,
                    path: String::new()
                }))
                .is_err(),
                "{fault}"
            );
        }
    }

    #[test]
    fn failed_or_disappearing_certificate_enumerations_are_rejected() {
        for fault in ["names", "disappeared"] {
            assert!(
                load_from(Some(&Fixture {
                    fault,
                    path: String::new()
                }))
                .is_err(),
                "{fault}"
            );
        }
    }
}
