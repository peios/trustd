//! The socket: `/run/trustd/trust.sock`.
//!
//! Everyone may connect and everyone may ask — the root set is public, and
//! in the default compat mode it is sitting in a world-readable file anyway.
//! What the control object gates is `reload`. Notably it does **not** gate
//! adding or distrusting a certificate: those are registry writes, checked
//! against the key's own descriptor, so `trust` and `reg` take the same path
//! and there is no second permission model to drift out of step with the
//! first.
//!
//! Replies chunk (§3.16): the root set is a few hundred kilobytes, so a
//! `roots` answer is a run of messages each carrying a batch and a `more`
//! flag. A subscriber gets a fresh run after every change.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

use libtrust::{MAX_MESSAGE_BYTES, ROOTS_PER_CHUNK, Reply, Request, Root, SOCKET_PATH, TRUSTD_RUN_DIR, TRUST_ALL_ACCESS, TRUST_CONTROL, TRUST_QUERY};
use peios::access::AccessCheck;
use peios::security::{AccessMask, AceFlags, AclBuilder, GenericMapping, SdBuilder, SecurityDescriptor, Sid, WellKnown};
use peios::token::Token;

use crate::log;

const DIRECTORY_MODE: u32 = 0o755;
const SOCKET_MODE: u32 = 0o666;
/// How long a client has to deliver its request.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a peer has to drain a reply before it is presumed gone. The
/// whole root set is a few hundred kilobytes and changes perhaps twice a
/// year, so a blocking write with a short deadline is simpler than
/// buffering, and a peer that cannot take it in this long is not coming
/// back.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections held at once, so a local flood exhausts a counter rather than
/// the descriptor table.
pub const MAX_CLIENTS: usize = 128;

pub fn listen() -> io::Result<UnixListener> {
    let directory = Path::new(TRUSTD_RUN_DIR);
    std::fs::create_dir_all(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(DIRECTORY_MODE))?;
    protect(directory);
    let path = Path::new(SOCKET_PATH);
    match std::fs::remove_file(path) {
        Ok(()) => log::warn(format_args!("removed a stale {SOCKET_PATH}")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    protect(path);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Let everyone reach the socket; the object check decides what they may do.
///
/// **The DACL only.** This used to set the owner to SYSTEM as well, which
/// is the one thing a LocalService process cannot do: making somebody else
/// the owner needs a privilege trustd does not have and should not have.
/// `set_sd` is all-or-nothing, so asking for the owner failed the whole
/// call with `EPERM` and the DACL was never written either — leaving
/// `/run/trustd` with peinit's descriptor, which admits SYSTEM,
/// Administrators and this service and nobody else, so an ordinary program
/// could not traverse it to reach the socket.
///
/// It failed silently since this shipped, because the error only went to
/// the log and a LocalService daemon's lines do not reach the console
/// (PEI-581). `evctl 'LOGS FROM trustd'` had them all along. Found while
/// verifying timed, which had inherited the same code.
pub fn protect(path: &Path) {
    use peios::file::SecInfo;
    let system = Sid::well_known(WellKnown::System);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let descriptor = AclBuilder::new()
        .allow(system.as_ref(), AccessMask::GENERIC_ALL.bits(), AceFlags::empty())
        .allow(
            everyone.as_ref(),
            AccessMask::GENERIC_READ.bits() | AccessMask::GENERIC_WRITE.bits() | AccessMask::GENERIC_EXECUTE.bits(),
            AceFlags::empty(),
        )
        .build()
        .and_then(|dacl| SdBuilder::new().dacl(&dacl).build());
    match descriptor {
        Ok(sd) => {
            if let Err(e) = peios::file::set_sd(None, path, SecInfo::DACL, &sd, 0) {
                log::error(format_args!(
                    "could not set a descriptor on {} ({e}); programs other than SYSTEM and \
                     administrators will not be able to reach the socket",
                    path.display()
                ));
            }
        }
        Err(e) => log::warn(format_args!("could not build a descriptor: {e}")),
    }
}

pub struct ControlObject {
    sd: SecurityDescriptor,
}

impl ControlObject {
    pub fn new(configured: Option<&[u8]>) -> ControlObject {
        if let Some(bytes) = configured {
            match SecurityDescriptor::from_validated_bytes(bytes.to_vec()) {
                Ok(sd) => return ControlObject { sd },
                Err(e) => log::warn(format_args!("ControlSecurity is not a valid descriptor ({e}); using the default")),
            }
        }
        ControlObject { sd: Self::default_sd() }
    }

    fn default_sd() -> SecurityDescriptor {
        let system = Sid::well_known(WellKnown::System);
        let administrators = Sid::well_known(WellKnown::Administrators);
        let everyone = Sid::well_known(WellKnown::Everyone);
        AclBuilder::new()
            .allow(system.as_ref(), TRUST_ALL_ACCESS, AceFlags::empty())
            .allow(administrators.as_ref(), TRUST_ALL_ACCESS, AceFlags::empty())
            .allow(everyone.as_ref(), TRUST_QUERY | AccessMask::READ_CONTROL.bits(), AceFlags::empty())
            .build()
            .and_then(|dacl| SdBuilder::new().owner(system.as_ref()).group(system.as_ref()).dacl(&dacl).build())
            .expect("the compiled default descriptor builds")
    }

    fn mapping() -> GenericMapping {
        let rc = AccessMask::READ_CONTROL.bits();
        GenericMapping::new(TRUST_QUERY | rc, TRUST_CONTROL | rc, TRUST_QUERY, TRUST_ALL_ACCESS)
    }

    pub fn permits(&self, stream: &UnixStream, right: u32) -> bool {
        let token = match Token::open_peer(stream.as_fd()) {
            Ok(t) => t,
            Err(e) => {
                log::warn(format_args!("control: no peer token: {e}"));
                return false;
            }
        };
        AccessCheck::new(&self.sd, AccessMask::from_bits_retain(right), Self::mapping())
            .token(token.as_fd())
            .check()
            .map(|d| d.allowed)
            .unwrap_or(false)
    }
}

/// A connection that has not yet delivered a whole request.
pub struct Client {
    pub stream: UnixStream,
    buf: Vec<u8>,
    pub since: Instant,
}

pub enum Progress {
    Incomplete,
    Request(Request),
    Closed,
}

impl Client {
    pub fn new(stream: UnixStream, now: Instant) -> Option<Client> {
        stream.set_nonblocking(true).ok()?;
        Some(Client { stream, buf: Vec::with_capacity(256), since: now })
    }

    pub fn read(&mut self) -> Progress {
        let mut chunk = [0u8; 4096];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => return Progress::Closed,
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    if self.buf.len() > 4 + MAX_MESSAGE_BYTES {
                        respond(&mut self.stream, &Reply::Error("request too large".into()));
                        return Progress::Closed;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Progress::Closed,
            }
        }
        if self.buf.len() < 4 {
            return Progress::Incomplete;
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_MESSAGE_BYTES {
            respond(&mut self.stream, &Reply::Error("request too large".into()));
            return Progress::Closed;
        }
        if self.buf.len() < 4 + len {
            return Progress::Incomplete;
        }
        match Request::decode(&self.buf[4..4 + len]) {
            Ok(r) => Progress::Request(r),
            Err(e) => {
                respond(&mut self.stream, &Reply::Error(e.to_string()));
                Progress::Closed
            }
        }
    }
}

/// Send one reply, blocking with a deadline.
pub fn respond(stream: &mut UnixStream, reply: &Reply) -> bool {
    write_message(stream, &reply.encode())
}

fn write_message(stream: &mut UnixStream, payload: &[u8]) -> bool {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    match stream.write_all(&frame) {
        Ok(()) => true,
        Err(e) => {
            log::warn(format_args!("control: reply failed: {e}"));
            false
        }
    }
}

/// Send the root set as a run of chunked messages. Returns false if the peer
/// went away, which is how a subscriber is dropped.
pub fn send_roots(stream: &mut UnixStream, generation: u64, roots: &[Root]) -> bool {
    if roots.is_empty() {
        return respond(stream, &Reply::Roots { generation, roots: Vec::new(), more: false });
    }
    let chunks: Vec<&[Root]> = roots.chunks(ROOTS_PER_CHUNK).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let reply = Reply::Roots {
            generation,
            roots: chunk.to_vec(),
            more: i + 1 < chunks.len(),
        };
        if !write_message(stream, &reply.encode()) {
            return false;
        }
    }
    true
}
