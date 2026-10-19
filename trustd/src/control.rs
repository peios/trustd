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

use peios::access::AccessCheck;
use peios::security::{AccessMask, AceFlags, AclBuilder, SdBuilder, SecurityDescriptor, Sid, WellKnown};
use peios::token::Token;
use trust_core::{
    MAX_MESSAGE_BYTES, ROOTS_PER_CHUNK, Reply, Request, Root, SOCKET_PATH, TRUSTD_RUN_DIR,
};

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
///
/// **trustd keeps full access for itself** (PEI-1373, as timed did in
/// c186b88). peinit leaves `/run/trustd` in place across a restart, and the
/// stale socket a previous run left behind has to be deleted before the new
/// one can bind. Everyone's read, write and execute include neither DELETE
/// nor deleting a child, so a descriptor of SYSTEM and Everyone alone gave a
/// trustd that started once and could never start again: every restart
/// failed with EACCES at the bind, until the restart budget was exhausted.
pub fn protect(path: &Path) {
    use peios::file::SecInfo;
    use peios::token::{Token, TokenAccess};
    let system = Sid::well_known(WellKnown::System);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let me = Token::open_self(true, TokenAccess::QUERY).and_then(|t| t.user());
    let mut acl = AclBuilder::new();
    acl.allow(
        system.as_ref(),
        AccessMask::GENERIC_ALL.bits(),
        AceFlags::empty(),
    );
    match &me {
        Ok(me) => {
            acl.allow(
                me.as_ref(),
                AccessMask::GENERIC_ALL.bits(),
                AceFlags::empty(),
            );
        }
        Err(e) => log::warn(format_args!(
            "could not read trustd's own identity ({e}); a restart may not be able to \
             replace {}",
            path.display()
        )),
    }
    acl.allow(
        everyone.as_ref(),
        AccessMask::GENERIC_READ.bits()
            | AccessMask::GENERIC_WRITE.bits()
            | AccessMask::GENERIC_EXECUTE.bits(),
        AceFlags::empty(),
    );
    let descriptor = acl
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
                Err(e) => log::warn(format_args!(
                    "ControlSecurity is not a valid descriptor ({e}); using the default"
                )),
            }
        }
        ControlObject {
            sd: trust_core::default_control_security(),
        }
    }

    pub fn permits(&self, stream: &UnixStream, right: u32) -> bool {
        let token = match Token::open_peer(stream.as_fd()) {
            Ok(t) => t,
            Err(e) => {
                log::warn(format_args!("control: no peer token: {e}"));
                return false;
            }
        };
        AccessCheck::new(
            &self.sd,
            AccessMask::from_bits_retain(right),
            trust_core::control_mapping(),
        )
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
        Some(Client {
            stream,
            buf: Vec::with_capacity(256),
            since: now,
        })
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
    write_message(stream, &reply.encode(), Instant::now() + WRITE_TIMEOUT)
}

fn write_message(stream: &mut UnixStream, payload: &[u8], end: Instant) -> bool {
    match write_frame(stream, payload, end) {
        Ok(()) => true,
        Err(error) => {
            log::warn(format_args!("control: reply failed: {error}"));
            false
        }
    }
}

fn write_frame(stream: &mut UnixStream, payload: &[u8], end: Instant) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "reply is too large"))?;
    stream.set_nonblocking(false)?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(payload);
    let mut pending = frame.as_slice();
    while !pending.is_empty() {
        let remaining = end
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "reply deadline expired"))?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(pending) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "peer stopped accepting reply",
                ));
            }
            Ok(count) => pending = &pending[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Send the root set as a run of chunked messages. Returns false if the peer
/// went away, which is how a subscriber is dropped.
pub fn send_roots(stream: &mut UnixStream, generation: u64, roots: &[Root]) -> bool {
    if roots.is_empty() {
        return respond(
            stream,
            &Reply::Roots {
                generation,
                roots: Vec::new(),
                more: false,
            },
        );
    }
    let end = Instant::now() + WRITE_TIMEOUT;
    let chunks: Vec<&[Root]> = roots.chunks(ROOTS_PER_CHUNK).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let reply = Reply::Roots {
            generation,
            roots: chunk.to_vec(),
            more: i + 1 < chunks.len(),
        };
        if !write_message(stream, &reply.encode(), end) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_snapshot_deadline_does_not_restart_for_another_frame() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        let end = Instant::now() + Duration::from_secs(1);
        write_frame(&mut writer, b"first", end).unwrap();
        let expired = Instant::now() - Duration::from_secs(1);
        let error = write_frame(&mut writer, b"second", expired).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(writer);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"\x05\0\0\0first");
    }

    #[test]
    fn a_stalled_peer_cannot_hold_a_reply_open() {
        let (mut writer, _reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let bytes = [0u8; 4096];
        loop {
            match writer.write(&bytes) {
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("filling socket: {error}"),
            }
        }
        let (sent, received) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = write_frame(
                &mut writer,
                b"reply",
                Instant::now() + Duration::from_millis(20),
            );
            sent.send(result).unwrap();
        });
        let error = received
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        worker.join().unwrap();
    }
}
