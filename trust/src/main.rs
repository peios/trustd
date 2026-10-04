//! trust — the trust store's operator command.
//!
//! ```text
//! trust list [--purpose P]        every root in force
//! trust list --distrusted        what this machine refuses, and why
//! trust show <fingerprint> [--pem] one root; --pem prints the certificate alone
//! trust status                    generation, counts, render state
//! trust add <name> <file|->       trust a certificate
//! trust remove <name>             undo an add
//! trust distrust <fp|file> [-r R] stop trusting a certificate, wherever it came from
//! trust restore <fp>              undo a distrust
//! trust reload                    recompose now
//! ```
//!
//! What each verb does is the `trust` library's, which Security Policy
//! shares; this is how a terminal asks for it and what it prints.

use std::io::Read;
use std::process::ExitCode;

use libtrust::{Root, Source};
use trust::{Error, cert, normalise_fingerprint};

/// What a refused step exits with: 2 for "not there", so a script can tell
/// "this machine does not trust that CA" from "I could not find out".
fn failed(error: Error) -> ExitCode {
    eprintln!("trust: {error}");
    match error {
        Error::NotFound(_) => ExitCode::from(2),
        _ => ExitCode::FAILURE,
    }
}

fn read_input(path: &str) -> Result<Vec<u8>, Error> {
    let bytes = if path == "-" {
        let mut buffer = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buffer)
            .map_err(|e| Error::Failed(format!("stdin: {e}")))?;
        buffer
    } else {
        std::fs::read(path).map_err(|e| Error::Failed(format!("{path}: {e}")))?
    };
    trust::certificate(&bytes, path)
}

fn add(name: &str, path: &str, purposes: &[String]) -> ExitCode {
    if !trust::usable_name(name) {
        eprintln!("trust: {name:?} is not a usable name");
        return ExitCode::FAILURE;
    }
    let der = match read_input(path) {
        Ok(der) => der,
        Err(e) => return failed(e),
    };
    if let Err(e) = trust::vet(&der) {
        eprintln!("trust: {path} is {e}");
        return ExitCode::FAILURE;
    }
    match trust::add(name, &der, purposes) {
        Ok(parsed) => {
            println!("added {name}");
            println!("  {}", parsed.subject);
            println!("  SHA-256 {}", parsed.fingerprint);
            if !purposes.is_empty() {
                println!("  for {}", purposes.join(", "));
            }
            ExitCode::SUCCESS
        }
        Err(e) => failed(e),
    }
}

fn remove(name: &str) -> ExitCode {
    match trust::remove(name) {
        Ok(()) => {
            println!("removed {name}");
            ExitCode::SUCCESS
        }
        Err(e) => failed(e),
    }
}

fn distrust(argument: &str, reason: &str) -> ExitCode {
    let fingerprint = match trust::resolve(argument) {
        Ok(f) => f,
        // An unmatched prefix is a mistake in what was typed, not an answer.
        Err(Error::NotFound(why)) => return failed(Error::Failed(why)),
        Err(e) => return failed(e),
    };
    match trust::distrust(&fingerprint, reason) {
        Ok(was) => {
            println!("distrusted {fingerprint}");
            match was {
                Some(subject) => println!("  was: {subject}"),
                None => println!(
                    "  no certificate in the store matched; the entry stays in force in case one arrives"
                ),
            }
            ExitCode::SUCCESS
        }
        Err(e) => failed(e),
    }
}

fn restore(argument: &str) -> ExitCode {
    match trust::restore(argument) {
        Ok(fingerprint) => {
            println!("restored {fingerprint}");
            ExitCode::SUCCESS
        }
        Err(e) => failed(e),
    }
}

fn list_distrusted() -> ExitCode {
    let entries = match trust::distrusted() {
        Ok(e) => e,
        Err(e) => return failed(e),
    };
    for entry in &entries {
        let short = &entry.fingerprint[..16.min(entry.fingerprint.len())];
        if entry.reason.is_empty() {
            println!("{short}  {}", entry.fingerprint);
        } else {
            println!("{short}  {}", entry.reason);
        }
    }
    println!();
    println!("{} distrusted", entries.len());
    ExitCode::SUCCESS
}

fn list(purpose: Option<String>) -> ExitCode {
    let list = match trust::roots(false, purpose) {
        Ok(list) => list,
        Err(e) => return failed(e),
    };
    for root in &list {
        let origin = match root.source {
            Source::Added => format!("added:{}", root.name.clone().unwrap_or_default()),
            Source::Shipped => "shipped".to_owned(),
        };
        println!(
            "{}  {:<9}  {}",
            &root.fingerprint[..16],
            origin,
            root.subject
        );
    }
    println!();
    println!("{} root(s)", list.len());
    ExitCode::SUCCESS
}

fn show(prefix: &str, pem_only: bool) -> ExitCode {
    let wanted = normalise_fingerprint(prefix);
    let list = match trust::roots(true, None) {
        Ok(list) => list,
        Err(e) => return failed(e),
    };
    let matches: Vec<&Root> = list
        .iter()
        .filter(|r| r.fingerprint.starts_with(&wanted))
        .collect();
    match matches.as_slice() {
        [] => {
            eprintln!("trust: no root in the store matches {prefix}");
            ExitCode::from(2)
        }
        [root] if pem_only => {
            print!("{}", cert::to_pem(&root.der));
            ExitCode::SUCCESS
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
            eprintln!(
                "trust: {prefix} matches {} roots; be more specific",
                many.len()
            );
            for root in many {
                eprintln!("  {}  {}", &root.fingerprint[..16], root.subject);
            }
            ExitCode::FAILURE
        }
    }
}

fn status() -> ExitCode {
    let status = match trust::status() {
        Ok(s) => s,
        Err(e) => return failed(e),
    };
    println!("generation   {}", status.generation);
    println!(
        "health       {}{}",
        status.health.as_str(),
        status
            .message
            .map(|m| format!(" — {m}"))
            .unwrap_or_default()
    );
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
    match trust::reload() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("trust: {e}");
            ExitCode::FAILURE
        }
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

fn version() -> ExitCode {
    println!("trust {}", env!("CARGO_PKG_VERSION"));
    ExitCode::SUCCESS
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
        .map(|v| {
            v.split(',')
                .map(|p| p.trim().to_owned())
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let pem_only = args.iter().any(|a| a == "--pem");
    args.retain(|a| a != "--pem");
    let reason = take_option(&mut args, "--reason")
        .or_else(|| take_option(&mut args, "-r"))
        .unwrap_or_default();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["--help"] | ["-h"] | ["help"] => {
            eprintln!(
                "usage: trust list [--purpose P] | show <fingerprint> [--pem] | status\n\
                 \x20      trust add <name> <file|-> [--purposes A,B] | remove <name>\n\
                 \x20      trust distrust <fingerprint|file> [--reason R] | restore <fingerprint>\n\
                 \x20      trust reload"
            );
            ExitCode::SUCCESS
        }
        ["--version"] | ["-V"] | ["version"] => version(),
        ["list"] => list(purpose),
        ["list", "--distrusted"] | ["distrusted"] => list_distrusted(),
        ["show", prefix] => show(prefix, pem_only),
        ["status"] => status(),
        ["add", name, path] => add(name, path, &purposes),
        ["remove", name] => remove(name),
        ["distrust", target] => distrust(target, &reason),
        ["restore", target] => restore(target),
        ["reload"] => reload(),
        _ => usage(),
    }
}
