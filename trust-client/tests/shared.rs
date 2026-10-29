//! Exercise the installed-style shared boundary with disposable Unix sockets.
use std::io::Write;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use trust_client::Client;
use trust_core::{Reply, Request};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket {
    directory: PathBuf,
    path: PathBuf,
    listener: UnixListener,
}
impl Socket {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "trust-api-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        Self {
            directory,
            path,
            listener,
        }
    }
    fn client(&self) -> Client {
        Client::new(&self.path, Duration::from_secs(2)).unwrap()
    }
    fn accept(&self) -> UnixStream {
        let (stream, _) = self.listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn receive(stream: &mut UnixStream) -> Request {
    Request::decode(&trust_core::recv(stream).unwrap()).unwrap()
}
fn frame(reply: &Reply) -> Vec<u8> {
    let bytes = reply.encode();
    let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
    out.extend(bytes);
    out
}
#[test]
fn invalid_connection_settings_are_rejected() {
    assert!(Client::new("", Duration::from_secs(1)).is_err());
    assert!(Client::new("/tmp/a\0b", Duration::from_secs(1)).is_err());
    assert!(Client::new("/tmp/a", Duration::ZERO).is_err());
    assert!(Client::new("/tmp/a", Duration::MAX).is_err());
}
#[test]
fn wrong_reply_type_is_rejected() {
    let socket = Socket::new();
    let client = socket.client();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        assert_eq!(receive(&mut stream), Request::Status);
        stream.write_all(&frame(&Reply::Ok)).unwrap();
    });
    assert_eq!(client.status().unwrap_err().code, libc::EINVAL);
    worker.join().unwrap();
}
#[test]
fn a_partial_reply_does_not_extend_the_total_deadline() {
    let socket = Socket::new();
    let client = Client::new(&socket.path, Duration::from_millis(30)).unwrap();
    let (finish, wait) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        assert_eq!(receive(&mut stream), Request::Status);
        stream.write_all(&[1, 0]).unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(2));
    });
    assert_eq!(client.status().unwrap_err().code, libc::ETIMEDOUT);
    finish.send(()).unwrap();
    worker.join().unwrap();
}
#[test]
fn subscription_timeout_preserves_a_partial_frame() {
    let socket = Socket::new();
    let client = socket.client();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        assert_eq!(receive(&mut stream), Request::Subscribe { with_der: false });
        let bytes = frame(&Reply::Roots {
            generation: 71,
            roots: vec![trust_core::Root {
                subject: "Example CA".into(),
                ..Default::default()
            }],
            more: false,
        });
        stream.write_all(&bytes[..2]).unwrap();
        ready_tx.send(()).unwrap();
        finish_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        stream.write_all(&bytes[2..]).unwrap();
    });
    let mut subscription = client.subscribe(false).unwrap();
    ready_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        subscription
            .next(Duration::from_millis(20))
            .unwrap_err()
            .code,
        libc::ETIMEDOUT
    );
    finish_tx.send(()).unwrap();
    let snapshot = subscription.next(Duration::from_secs(2)).unwrap();
    assert_eq!(snapshot.generation, 71);
    worker.join().unwrap();
}
#[test]
fn roots_from_different_generations_are_not_combined() {
    let socket = Socket::new();
    let client = socket.client();
    let worker = std::thread::spawn(move || {
        let mut stream = socket.accept();
        receive(&mut stream);
        stream
            .write_all(&frame(&Reply::Roots {
                generation: 1,
                roots: vec![],
                more: true,
            }))
            .unwrap();
        stream
            .write_all(&frame(&Reply::Roots {
                generation: 2,
                roots: vec![],
                more: false,
            }))
            .unwrap();
    });
    assert_eq!(client.roots(false, None).unwrap_err().code, libc::EINVAL);
    worker.join().unwrap();
}
#[test]
fn certificate_details_cross_the_shared_boundary() {
    let pem = include_bytes!("../../trust-core/tests/fixtures/comodo-ecc.pem");
    let der = trust_client::certificate(pem, "fixture").unwrap();
    let expected = trust_core::cert::describe(&der).unwrap();
    let actual = trust_client::inspect(&der).unwrap();
    assert_eq!(actual.subject, expected.subject);
    assert_eq!(actual.serial, expected.serial);
    assert!(actual.ca);
    assert!(!actual.subject.is_empty());
}
#[test]
fn a_refused_certificate_says_why_by_kind() {
    let leaf = include_bytes!("../../trust-core/tests/fixtures/leaf.pem");
    let leaf = trust_client::certificate(leaf, "leaf").unwrap();
    let refused = trust_client::vet(&leaf).unwrap_err();
    assert_eq!(refused.kind, trust_client::ErrorKind::NotACa);
    assert_eq!(refused.code, libc::EINVAL);
    let expired = include_bytes!("../../trust-core/tests/fixtures/expired-ca.pem");
    let expired = trust_client::certificate(expired, "expired").unwrap();
    assert_eq!(
        trust_client::vet(&expired).unwrap_err().kind,
        trust_client::ErrorKind::Expired
    );
    assert_eq!(
        trust_client::vet(b"not a certificate").unwrap_err().kind,
        trust_client::ErrorKind::Malformed
    );
    assert_eq!(
        trust_client::inspect(b"not a certificate")
            .unwrap_err()
            .kind,
        trust_client::ErrorKind::Malformed
    );
    let ca = include_bytes!("../../trust-core/tests/fixtures/comodo-ecc.pem");
    let ca = trust_client::certificate(ca, "ca").unwrap();
    assert!(trust_client::vet(&ca).is_ok());
}
#[test]
fn certificates_cross_as_pem_and_fingerprints_as_the_core_makes_them() {
    let pem = include_str!("../../trust-core/tests/fixtures/comodo-ecc.pem");
    let der = trust_client::certificate(pem.as_bytes(), "fixture").unwrap();
    assert_eq!(
        trust_client::fingerprint(&der).unwrap(),
        trust_core::cert::fingerprint(&der)
    );
    let written = trust_client::to_pem(&der).unwrap();
    assert_eq!(written, trust_core::cert::to_pem(&der));
    let bundle = format!(
        "# a comment the shipped bundle has\n{written}{}",
        include_str!("../../trust-core/tests/fixtures/netlock-arany.pem")
    );
    let read = trust_client::from_pem(&bundle).unwrap();
    assert_eq!(read.len(), 2);
    assert_eq!(read[0], der);
    assert!(trust_client::from_pem("no blocks").unwrap().is_empty());
}
#[test]
fn a_fingerprint_prefix_resolves_against_the_roots_given() {
    let root = |fingerprint: &str| trust_core::Root {
        fingerprint: fingerprint.into(),
        ..Default::default()
    };
    let a = format!("018e13f0{}", "a".repeat(56));
    let b = format!("018e13f1{}", "b".repeat(56));
    let roots = [root(&a), root(&b)];
    assert_eq!(
        trust_client::fingerprint_in("01:8E:13:F0", &roots).unwrap(),
        a
    );
    assert_eq!(
        trust_client::fingerprint_in("deadbeef", &roots)
            .unwrap_err()
            .kind,
        trust_client::ErrorKind::NotFound
    );
    assert_eq!(
        trust_client::fingerprint_in("018e13f", &roots)
            .unwrap_err()
            .kind,
        trust_client::ErrorKind::Other
    );
    let whole = "c".repeat(64);
    assert_eq!(trust_client::fingerprint_in(&whole, &roots).unwrap(), whole);
    assert_eq!(
        trust_client::normalise_fingerprint("01:8E 13-F0").unwrap(),
        "018e13f0"
    );
}
#[test]
fn the_default_control_descriptor_is_the_cores() {
    assert_eq!(
        trust_client::default_control_security().unwrap(),
        trust_core::default_control_security().as_bytes()
    );
}
