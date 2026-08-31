//! trust — the trust store's operator command.
//!
//! ```text
//! trust list [--purpose P]        every root in force
//! trust list --distrusted        what this machine refuses, and why
//! trust show <fingerprint>        one root, with its certificate
//! trust status                    generation, counts, render state
//! trust add <name> <file|->       trust a certificate
//! trust remove <name>             undo an add
//! trust distrust <fp|file> [-r R] stop trusting a certificate, wherever it came from
//! trust restore <fp>              undo a distrust
//! trust reload                    recompose now
//! ```
//!
//! It reads over trustd's socket and writes to the registry, and the split
//! is deliberate. Only trustd knows the *effective* set — the shipped roots
//! are package data, not registry entries, so a listing read from the
//! registry would show the handful of local decisions and none of the
//! hundred and fifty roots actually in force. Writes go the other way: to
//! the registry, exactly as `reg` would write them, so the key's own
//! descriptor is the only thing that decides who may change what this
//! machine trusts. There is no second permission model here to drift out of
//! step with that one.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use libtrust::{
    ADD_KEY, CERTIFICATE_VALUE, CERTIFICATES_KEY, DISTRUST_KEY, PURPOSES_VALUE, Reply, Request, Root, SOCKET_PATH, Source,
};
use peios::registry::{CreateFlags, Key, KeyAccess, ValueType};
use trustd::cert;
use trustd::store::normalise_fingerprint;

const ACCESS: KeyAccess = KeyAccess::QUERY_VALUE
    .union(KeyAccess::SET_VALUE)
    .union(KeyAccess::CREATE_SUB_KEY)
    .union(KeyAccess::ENUMERATE_SUB_KEYS);

// ------------------------------------------------------------- the socket ---

fn call(request: &Request) -> Result<Vec<Reply>, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("trustd is not reachable at {SOCKET_PATH}: {e}"))?;
    libtrust::call(&mut stream, request).map_err(|e| e.to_string())
}

fn roots(with_der: bool, purpose: Option<String>) -> Result<Vec<Root>, String> {
    libtrust::roots_of(call(&Request::Roots { with_der, purpose })?).map(|(_, roots)| roots)
}

// ------------------------------------------------------------ the registry ---

fn open_or_create(path: &str) -> Result<Key, String> {
    Key::create(None, path, ACCESS, CreateFlags::empty(), None, None)
        .map(|(k, _)| k)
        .map_err(|e| describe_registry_error(path, e))
}

fn open_or_create_under(parent: &Key, name: &str) -> Result<Key, String> {
    Key::create(Some(parent), name, ACCESS, CreateFlags::empty(), None, None)
        .map(|(k, _)| k)
        .map_err(|e| describe_registry_error(name, e))
}

/// A denied registry write is the expected failure for a person who may not
/// change the machine's trust, so it should say so rather than print an
/// error number.
fn describe_registry_error(path: &str, error: peios::Error) -> String {
    if error.raw_os_error() == Some(libc::EACCES) || error.raw_os_error() == Some(libc::EPERM) {
        format!("not permitted to change {path} — changing what this machine trusts is governed by that key's descriptor")
    } else {
        format!("{path}: {error}")
    }
}

/// `Machine\System\Trust\Certificates\<Add|Distrust>`, created if absent.
fn certificates(which: &str) -> Result<Key, String> {
    let certificates = open_or_create(CERTIFICATES_KEY)?;
    open_or_create_under(&certificates, which)
}

// ------------------------------------------------------------------ verbs ---

fn read_input(path: &str) -> Result<Vec<u8>, String> {
    let text = if path == "-" {
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer).map_err(|e| format!("stdin: {e}"))?;
        buffer
    } else {
        std::fs::read(path).map_err(|e| format!("{path}: {e}"))?
    };
    // PEM if it looks like it, DER otherwise.
    if let Ok(as_text) = std::str::from_utf8(&text) {
        let certificates = cert::from_pem(as_text);
        if certificates.len() > 1 {
            return Err(format!("{path} holds {} certificates; add them one at a time", certificates.len()));
        }
        if let Some(der) = certificates.into_iter().next() {
            return Ok(der);
        }
    }
    Ok(text)
}

fn add(name: &str, path: &str, purposes: &[String]) -> ExitCode {
    if name.is_empty() || name.contains('\\') || name.contains('/') {
        eprintln!("trust: {name:?} is not a usable name");
        return ExitCode::FAILURE;
    }
    let der = match read_input(path) {
        Ok(der) => der,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Validate here as well as in trustd, so a mistake is reported now
    // rather than discovered in a log. trustd re-validates regardless: it
    // never trusts the writer.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .ok();
    let parsed = match cert::parse(&der, now) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("trust: {path} is {e}");
            return ExitCode::FAILURE;
        }
    };

    let add = match certificates(ADD_KEY).and_then(|add| open_or_create_under(&add, name)) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !purposes.is_empty() {
        let mut data = Vec::new();
        for purpose in purposes {
            data.extend_from_slice(purpose.as_bytes());
            data.push(0);
        }
        data.push(0);
        if let Err(e) = add.set_value(PURPOSES_VALUE.as_bytes(), ValueType::MULTI_SZ, &data).call() {
            eprintln!("trust: could not set {PURPOSES_VALUE}: {e}");
            return ExitCode::FAILURE;
        }
    }
    // The certificate goes last: until it exists the entry is incomplete,
    // and trustd skips incomplete entries rather than acting on half of one.
    if let Err(e) = add.set_value(CERTIFICATE_VALUE.as_bytes(), ValueType::BINARY, &der).call() {
        eprintln!("trust: could not set {CERTIFICATE_VALUE}: {e}");
        return ExitCode::FAILURE;
    }
    println!("added {name}");
    println!("  {}", parsed.subject);
    println!("  SHA-256 {}", parsed.fingerprint);
    if !purposes.is_empty() {
        println!("  for {}", purposes.join(", "));
    }
    ExitCode::SUCCESS
}

fn remove(name: &str) -> ExitCode {
    let add = match certificates(ADD_KEY) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    let entry = match Key::open(Some(&add), name, KeyAccess::DELETE, peios::registry::OpenFlags::empty()) {
        Ok(key) => key,
        Err(_) => {
            eprintln!("trust: no addition named {name}");
            return ExitCode::from(2);
        }
    };
    match entry.delete_key(None, None) {
        Ok(()) => {
            println!("removed {name}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("trust: {}", describe_registry_error(&format!("{CERTIFICATES_KEY}\\{ADD_KEY}\\{name}"), e));
            ExitCode::FAILURE
        }
    }
}

/// The fingerprint to act on, from a whole fingerprint, a prefix of one as
/// `trust list` prints it, or a certificate file.
///
/// A prefix is resolved against the store, so what `list` shows can be
/// pasted straight back in. An ambiguous prefix is refused rather than
/// guessed at: distrusting the wrong certificate is not a mistake worth
/// being convenient about.
fn target_fingerprint(argument: &str) -> Result<String, String> {
    let normalised = normalise_fingerprint(argument);
    let looks_hex = !normalised.is_empty() && normalised.bytes().all(|b| b.is_ascii_hexdigit());
    if looks_hex && normalised.len() == 64 {
        return Ok(normalised);
    }
    if looks_hex && normalised.len() >= 8 {
        let list = roots(false, None)?;
        let matches: Vec<&Root> = list.iter().filter(|r| r.fingerprint.starts_with(&normalised)).collect();
        return match matches.as_slice() {
            [root] => Ok(root.fingerprint.clone()),
            [] => Err(format!(
                "no certificate in the store starts with {normalised} — give the whole fingerprint if you mean one the store does not have"
            )),
            many => Err(format!("{normalised} matches {} certificates; be more specific", many.len())),
        };
    }
    let der = read_input(argument)?;
    let parsed = cert::parse(&der, None)
        .map_err(|e| format!("{argument} is neither a SHA-256 fingerprint nor a certificate ({e})"))?;
    Ok(parsed.fingerprint)
}

fn distrust(argument: &str, reason: &str) -> ExitCode {
    let fingerprint = match target_fingerprint(argument) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    let key = match certificates(DISTRUST_KEY) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    // Look before writing: afterwards trustd has already dropped the
    // certificate, so asking then would always answer "no match" and say
    // the opposite of the truth.
    let was = roots(false, None)
        .ok()
        .and_then(|list| list.into_iter().find(|r| r.fingerprint == fingerprint).map(|r| r.subject));
    let mut data = reason.as_bytes().to_vec();
    data.push(0);
    if let Err(e) = key.set_value(fingerprint.as_bytes(), ValueType::SZ, &data).call() {
        eprintln!("trust: could not write the distrust: {e}");
        return ExitCode::FAILURE;
    }
    println!("distrusted {fingerprint}");
    // Distrusting a certificate the machine does not have is legitimate —
    // the entry waits in case one arrives — and looks identical otherwise,
    // so say which happened.
    match was {
        Some(subject) => println!("  was: {subject}"),
        None => println!("  no certificate in the store matched; the entry stays in force in case one arrives"),
    }
    ExitCode::SUCCESS
}

/// Every fingerprint under `Distrust\`, with its reason.
///
/// Read from the registry rather than the socket: a distrusted certificate
/// is by definition not in the store, so the daemon cannot answer for it.
fn distrust_entries() -> Result<Vec<(String, String)>, String> {
    let key = certificates(DISTRUST_KEY)?;
    let mut out = Vec::new();
    for value in key.values(None) {
        let Ok(value) = value else { continue };
        let Ok(name) = String::from_utf8(value.name.clone()) else { continue };
        let end = value.data.iter().position(|&b| b == 0).unwrap_or(value.data.len());
        let reason = String::from_utf8_lossy(&value.data[..end]).into_owned();
        out.push((normalise_fingerprint(&name), reason));
    }
    out.sort();
    Ok(out)
}

fn restore(argument: &str) -> ExitCode {
    let normalised = normalise_fingerprint(argument);
    let fingerprint = if normalised.len() == 64 {
        normalised
    } else {
        // Resolve against what is distrusted, not against the store.
        match distrust_entries() {
            Ok(entries) => {
                let matches: Vec<&(String, String)> =
                    entries.iter().filter(|(f, _)| f.starts_with(&normalised)).collect();
                match matches.as_slice() {
                    [(f, _)] => f.clone(),
                    [] => {
                        eprintln!("trust: nothing distrusted starts with {normalised}");
                        return ExitCode::from(2);
                    }
                    many => {
                        eprintln!("trust: {normalised} matches {} distrust entries; be more specific", many.len());
                        return ExitCode::FAILURE;
                    }
                }
            }
            Err(e) => {
                eprintln!("trust: {e}");
                return ExitCode::FAILURE;
            }
        }
    };
    let key = match certificates(DISTRUST_KEY) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    match key.delete_value(fingerprint.as_bytes(), None, None) {
        Ok(()) => {
            println!("restored {fingerprint}");
            ExitCode::SUCCESS
        }
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
            eprintln!("trust: {fingerprint} is not distrusted");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("trust: {}", describe_registry_error(&format!("{CERTIFICATES_KEY}\\{DISTRUST_KEY}"), e));
            ExitCode::FAILURE
        }
    }
}

fn list_distrusted() -> ExitCode {
    let entries = match distrust_entries() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    for (fingerprint, reason) in &entries {
        if reason.is_empty() {
            println!("{}  {fingerprint}", &fingerprint[..16.min(fingerprint.len())]);
        } else {
            println!("{}  {reason}", &fingerprint[..16.min(fingerprint.len())]);
        }
    }
    println!();
    println!("{} distrusted", entries.len());
    ExitCode::SUCCESS
}

fn list(purpose: Option<String>) -> ExitCode {
    let list = match roots(false, purpose) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    for root in &list {
        let origin = match root.source {
            Source::Added => format!("added:{}", root.name.clone().unwrap_or_default()),
            Source::Shipped => "shipped".to_owned(),
        };
        println!("{}  {:<9}  {}", &root.fingerprint[..16], origin, root.subject);
    }
    println!();
    println!("{} root(s)", list.len());
    ExitCode::SUCCESS
}

fn show(prefix: &str) -> ExitCode {
    let wanted = normalise_fingerprint(prefix);
    let list = match roots(true, None) {
        Ok(list) => list,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    let matches: Vec<&Root> = list.iter().filter(|r| r.fingerprint.starts_with(&wanted)).collect();
    match matches.as_slice() {
        [] => {
            eprintln!("trust: no root in the store matches {prefix}");
            ExitCode::from(2)
        }
        [root] => {
            println!("subject      {}", root.subject);
            println!("fingerprint  {}", root.fingerprint);
            println!("source       {}", root.source.as_str());
            if let Some(name) = &root.name {
                println!("added as     {name}");
            }
            println!("purposes     {}", root.purposes.join(", "));
            println!("expires      {}", root.not_after);
            println!();
            print!("{}", cert::to_pem(&root.der));
            ExitCode::SUCCESS
        }
        many => {
            eprintln!("trust: {prefix} matches {} roots; be more specific", many.len());
            for root in many {
                eprintln!("  {}  {}", &root.fingerprint[..16], root.subject);
            }
            ExitCode::FAILURE
        }
    }
}

fn status() -> ExitCode {
    let replies = match call(&Request::Status) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
    };
    let status = match replies.into_iter().next() {
        Some(Reply::Status(s)) => s,
        Some(Reply::Error(e)) => {
            eprintln!("trust: {e}");
            return ExitCode::FAILURE;
        }
        _ => return ExitCode::FAILURE,
    };
    println!("generation   {}", status.generation);
    println!("health       {}{}", status.health.as_str(), status.message.map(|m| format!(" — {m}")).unwrap_or_default());
    println!("roots        {} in force", status.effective);
    println!("  shipped    {}", status.shipped);
    println!("  added      {}", status.added);
    println!("  distrusted {}", status.distrusted);
    if status.skipped > 0 {
        println!("  skipped    {} (unusable; see the log)", status.skipped);
    }
    println!(
        "compat       GenerateLinuxTrustFiles = {}{}",
        status.compat_mode,
        match status.compat_mode {
            0 => " (no files; the socket is the only store)",
            2 => " (reserved)",
            _ => "",
        }
    );
    for path in &status.rendered {
        println!("  rendered   {path}");
    }
    ExitCode::SUCCESS
}

fn reload() -> ExitCode {
    match call(&Request::Reload).map(|r| r.into_iter().next()) {
        Ok(Some(Reply::Ok)) => ExitCode::SUCCESS,
        Ok(Some(Reply::Error(e))) | Err(e) => {
            eprintln!("trust: {e}");
            ExitCode::FAILURE
        }
        _ => ExitCode::FAILURE,
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: trust list [--purpose P] | show <fingerprint> | status\n\
         \x20      trust add <name> <file|-> [--purposes A,B] | remove <name>\n\
         \x20      trust distrust <fingerprint|file> [--reason R] | restore <fingerprint>\n\
         \x20      trust reload"
    );
    ExitCode::from(64)
}

/// Pull `--flag value` out of the arguments, leaving the positionals.
fn take_option(args: &mut Vec<String>, flag: &str) -> Option<String> {
    let at = args.iter().position(|a| a == flag)?;
    if at + 1 >= args.len() {
        return None;
    }
    let value = args.remove(at + 1);
    args.remove(at);
    Some(value)
}

fn main() -> ExitCode {
    // Rust's runtime ignores SIGPIPE, so writing to a closed pipe raises an
    // error that the print macros turn into a panic — `trust show | head`
    // ends in a backtrace instead of stopping. Restore the default.
    // SAFETY: setting a signal disposition before any thread is started.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let purpose = take_option(&mut args, "--purpose");
    let purposes = take_option(&mut args, "--purposes")
        .map(|v| v.split(',').map(|p| p.trim().to_owned()).filter(|p| !p.is_empty()).collect::<Vec<_>>())
        .unwrap_or_default();
    let reason = take_option(&mut args, "--reason")
        .or_else(|| take_option(&mut args, "-r"))
        .unwrap_or_default();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["list"] => list(purpose),
        ["list", "--distrusted"] | ["distrusted"] => list_distrusted(),
        ["show", prefix] => show(prefix),
        ["status"] => status(),
        ["add", name, path] => add(name, path, &purposes),
        ["remove", name] => remove(name),
        ["distrust", target] => distrust(target, &reason),
        ["restore", target] => restore(target),
        ["reload"] => reload(),
        _ => usage(),
    }
}
