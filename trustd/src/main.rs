//! trustd — the Peios trust store.
//!
//! One thread, one `poll`. Inputs: the socket, the registry watch on
//! `Machine\System\Trust`, and a periodic look at the shipped bundle so a
//! package upgrade is noticed without a reboot. On any of them the store is
//! recomposed from scratch and, if anything changed, re-rendered and pushed
//! to every subscriber.
//!
//! The daemon holds no private key and no secret. Everything it serves is
//! public, which is why its socket is open to all and why it can run with no
//! privileges at all.

mod config;
mod control;

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use libtrust::{Health, Reply, Request, Root, SHARE_BUNDLE, STORE_DIR, Status};
use peios::registry::Key;
use trustd::log;
use trustd::render;
use trustd::store::{self, Composed};

/// How often to look at the shipped bundle. A package upgrade replaces it
/// and nothing tells us; a stat every minute is cheaper than any mechanism
/// that would.
const BUNDLE_POLL: Duration = Duration::from_secs(60);

struct Trustd {
    config: config::Config,
    control: control::ControlObject,
    composed: Composed,
    generation: u64,
    health: Health,
    message: Option<String>,
    rendered: Vec<String>,
    bundle_stamp: Option<(u64, i64)>,
    clients: HashMap<u64, control::Client>,
    /// Connections held open by `subscribe`, owed a fresh set on every
    /// change.
    subscribers: Vec<(UnixStream, bool)>,
    next_id: u64,
}

impl Trustd {
    fn fresh_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// The wire form of the current set.
    fn roots(&self, with_der: bool, purpose: Option<&str>) -> Vec<Root> {
        self.composed
            .roots
            .iter()
            .filter(|entry| match purpose {
                Some(p) => entry.purposes.iter().any(|own| own.eq_ignore_ascii_case(p)),
                None => true,
            })
            .map(|entry| Root {
                fingerprint: entry.parsed.fingerprint.clone(),
                subject: entry.parsed.subject.clone(),
                purposes: entry.purposes.clone(),
                source: entry.source,
                name: entry.name.clone(),
                not_after: entry.parsed.not_after,
                der: if with_der {
                    entry.parsed.der.clone()
                } else {
                    Vec::new()
                },
            })
            .collect()
    }

    fn status(&self) -> Status {
        Status {
            generation: self.generation,
            health: self.health,
            message: self.message.clone(),
            shipped: self.composed.shipped,
            added: self.composed.added,
            distrusted: self.composed.distrusted,
            skipped: self.composed.skipped,
            effective: self.composed.roots.len() as u64,
            compat_mode: self.config.compat.as_dword(),
            rendered: self.rendered.clone(),
        }
    }

    /// Recompose from the registry and the shipped bundle, render if the
    /// result differs from what is already out there, and tell subscribers.
    fn refresh(&mut self, reason: &str) {
        let fresh = config::load();
        let config_changed = fresh != self.config;
        if config_changed {
            self.control = control::ControlObject::new(fresh.control_security.as_deref());
        }
        self.config = fresh;
        self.bundle_stamp = render::stamp(Path::new(SHARE_BUNDLE));

        let shipped = match std::fs::read_to_string(SHARE_BUNDLE) {
            Ok(text) => text,
            Err(e) => {
                // Keep whatever is rendered: stale beats absent, and absent
                // would break every TLS client on the machine at once.
                self.degrade(format!("cannot read {SHARE_BUNDLE}: {e}"));
                return;
            }
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .ok();
        let composed =
            match store::compose(&shipped, &self.config.additions, &self.config.distrust, now) {
                Ok(c) => c,
                Err(e) => {
                    self.degrade(e);
                    return;
                }
            };

        let unchanged = composed.roots == self.composed.roots && self.health == Health::Ok;
        for warning in &composed.warnings {
            log::warn(format_args!("{warning}"));
        }
        self.composed = composed;
        self.health = Health::Ok;
        self.message = None;

        // The rendering is a pure function of the store and the mode, so an
        // unchanged store rewrites nothing — but a changed *mode* still has
        // to be applied.
        let mode_changed = config_changed;
        if unchanged && !mode_changed {
            return;
        }
        self.generation += 1;
        log::info(format_args!(
            "{reason}: {} root(s) — {} shipped, {} added, {} distrusted, {} skipped (generation {})",
            self.composed.roots.len(),
            self.composed.shipped,
            self.composed.added,
            self.composed.distrusted,
            self.composed.skipped,
            self.generation
        ));
        self.render();
        self.publish();
    }

    fn degrade(&mut self, why: String) {
        log::error(format_args!("{why}; keeping the last rendered store"));
        self.health = Health::Degraded;
        self.message = Some(why);
    }

    fn render(&mut self) {
        match render::render(Path::new(STORE_DIR), &self.composed, self.config.compat) {
            Ok(paths) => {
                // No descriptor is stamped here on purpose. The store
                // directory carries an inheritable one — SYSTEM and
                // Administrators full, Everyone read, trustd full — so
                // every file the renderer writes comes out readable by the
                // software that needs it and writable by the next render.
                // Stamping our own would drop trustd's access to the file
                // it had just written.
                if paths.is_empty() {
                    log::info(format_args!(
                        "GenerateLinuxTrustFiles is 0; no files are rendered"
                    ));
                } else {
                    log::info(format_args!("rendered {}", paths.join(", ")));
                }
                self.rendered = render::rendered_paths(Path::new(STORE_DIR));
            }
            Err(e) => {
                self.health = Health::Degraded;
                self.message = Some(format!("render failed: {e}"));
                log::error(format_args!("render failed: {e}"));
            }
        }
    }

    /// Hand every subscriber the new set. One that cannot take it is gone.
    fn publish(&mut self) {
        if self.subscribers.is_empty() {
            return;
        }
        let generation = self.generation;
        let with_der = self.roots(true, None);
        let without = self.roots(false, None);
        let mut kept = Vec::with_capacity(self.subscribers.len());
        for (mut stream, wants_der) in std::mem::take(&mut self.subscribers) {
            let roots = if wants_der { &with_der } else { &without };
            if control::send_roots(&mut stream, generation, roots) {
                kept.push((stream, wants_der));
            } else {
                log::warn(format_args!("a subscriber went away"));
            }
        }
        self.subscribers = kept;
    }

    fn handle(&mut self, mut stream: UnixStream, request: Request) {
        if !self.control.permits(&stream, request.required_right()) {
            control::respond(&mut stream, &Reply::Error("access denied".into()));
            return;
        }
        match request {
            Request::Status => {
                control::respond(&mut stream, &Reply::Status(self.status()));
            }
            Request::Roots { with_der, purpose } => {
                let roots = self.roots(with_der, purpose.as_deref());
                control::send_roots(&mut stream, self.generation, &roots);
            }
            Request::Subscribe { with_der } => {
                let roots = self.roots(with_der, None);
                if control::send_roots(&mut stream, self.generation, &roots) {
                    self.subscribers.push((stream, with_der));
                }
            }
            Request::Reload => {
                self.refresh("reload requested");
                control::respond(&mut stream, &Reply::Ok);
            }
        }
    }
}

fn notify_ready() {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else {
        return;
    };
    match UnixDatagram::unbound() {
        Ok(s) => {
            if let Err(e) = s.send_to(b"READY=1", &path) {
                log::warn(format_args!("readiness notify: {e}"));
            }
        }
        Err(e) => log::warn(format_args!("readiness notify: {e}")),
    }
}

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V" | "version") => {
            println!("trustd {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h" | "help") => {
            eprintln!("usage: trustd");
            return ExitCode::SUCCESS;
        }
        Some(argument) => {
            eprintln!("trustd: unexpected argument: {argument}");
            eprintln!("usage: trustd");
            return ExitCode::from(64);
        }
        None => {}
    }

    let listener = match control::listen() {
        Ok(l) => l,
        Err(e) => {
            log::error(format_args!("control socket: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let mut watch: Option<Key> = match config::watch() {
        Ok(k) => Some(k),
        Err(e) => {
            log::warn(format_args!(
                "registry watch unavailable ({e}); configuration is read on a timer only"
            ));
            None
        }
    };
    let config = config::load();
    let control = control::ControlObject::new(config.control_security.as_deref());
    let mut trustd = Trustd {
        config,
        control,
        composed: Composed::default(),
        generation: 0,
        health: Health::Ok,
        message: None,
        rendered: Vec::new(),
        bundle_stamp: None,
        clients: HashMap::new(),
        subscribers: Vec::new(),
        next_id: 0,
    };
    trustd.refresh("start");
    if trustd.health == Health::Degraded {
        // Starting degraded is survivable — the previous boot's render may
        // still be there on an installed machine — but it must be loud.
        log::error(format_args!(
            "started with no usable store: {}",
            trustd.message.clone().unwrap_or_default()
        ));
    }
    notify_ready();

    let mut watch_buffer = vec![0u8; 16384];
    loop {
        let mut fds: Vec<libc::pollfd> = Vec::new();
        fn push(fds: &mut Vec<libc::pollfd>, fd: i32) -> usize {
            fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
            fds.len() - 1
        }
        push(&mut fds, listener.as_raw_fd());
        let watch_slot = watch.as_ref().map(|w| push(&mut fds, w.as_raw_fd()));
        let client_slots: Vec<(u64, usize)> = trustd
            .clients
            .iter()
            .map(|(id, c)| (*id, push(&mut fds, c.stream.as_raw_fd())))
            .collect();
        // A subscriber that closes its end should not sit in the table until
        // the next change; poll it so the close is noticed.
        let subscriber_slots: Vec<usize> = trustd
            .subscribers
            .iter()
            .map(|(s, _)| push(&mut fds, s.as_raw_fd()))
            .collect();

        let timeout = BUNDLE_POLL.as_millis() as i32;
        // SAFETY: `fds` is a live, exclusively borrowed array for the call.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            log::error(format_args!("poll: {e}"));
            return ExitCode::FAILURE;
        }
        let now = Instant::now();

        if fds[0].revents != 0 {
            loop {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if trustd.clients.len() >= control::MAX_CLIENTS {
                            drop(stream);
                            continue;
                        }
                        if let Some(client) = control::Client::new(stream, now) {
                            let id = trustd.fresh_id();
                            trustd.clients.insert(id, client);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::warn(format_args!("accept: {e}"));
                        break;
                    }
                }
            }
        }

        for (id, slot) in &client_slots {
            if fds[*slot].revents == 0 {
                continue;
            }
            let Some(client) = trustd.clients.get_mut(id) else {
                continue;
            };
            match client.read() {
                control::Progress::Incomplete => {}
                control::Progress::Closed => {
                    trustd.clients.remove(id);
                }
                control::Progress::Request(request) => {
                    let client = trustd.clients.remove(id).expect("present");
                    trustd.handle(client.stream, request);
                }
            }
        }

        // A readable subscriber has closed (it never sends anything).
        let mut closed = Vec::new();
        for (i, slot) in subscriber_slots.iter().enumerate() {
            if fds[*slot].revents != 0 {
                closed.push(i);
            }
        }
        for i in closed.into_iter().rev() {
            trustd.subscribers.remove(i);
        }

        let mut refresh = None;
        if let Some(slot) = watch_slot {
            if fds[slot].revents != 0 {
                if let Some(w) = &watch {
                    match w.read_watch_events(&mut watch_buffer) {
                        Ok(events) if !events.is_empty() => refresh = Some("the registry changed"),
                        Ok(_) => {}
                        Err(e) => {
                            log::warn(format_args!("registry watch: {e}; re-arming"));
                            watch = config::watch().ok();
                        }
                    }
                }
            }
        }
        // A package upgrade replaces the shipped bundle underneath us.
        if refresh.is_none() && render::stamp(Path::new(SHARE_BUNDLE)) != trustd.bundle_stamp {
            refresh = Some("the shipped bundle changed");
        }
        if let Some(reason) = refresh {
            trustd.refresh(reason);
        }

        trustd
            .clients
            .retain(|_, c| now.duration_since(c.since) < control::CLIENT_TIMEOUT);
    }
}
