//! Does a real TLS client validate a real chain against the rendered store?
//!
//! This is the question the whole trust store exists to answer, and no
//! amount of checking that files exist answers it. The probe loads
//! `/etc/ssl/certs/ca-certificates.crt` — the compat rendering trustd
//! writes, read exactly as any other program would read it — into rustls,
//! and completes a handshake with a public host.
//!
//! It also proves the negative: with an empty root store the same handshake
//! must fail. A probe that only ever succeeds cannot tell a working trust
//! store from a client that is not checking.

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

const BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

fn roots_from(path: &str) -> Result<rustls::RootCertStore, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut reader = std::io::BufReader::new(file);
    let mut store = rustls::RootCertStore::empty();
    let mut loaded = 0;
    for certificate in rustls_pemfile::certs(&mut reader) {
        let certificate = certificate.map_err(|e| format!("{path}: {e}"))?;
        if store.add(certificate).is_ok() {
            loaded += 1;
        }
    }
    println!("loaded {loaded} root(s) from {path}");
    Ok(store)
}

fn handshake(host: &str, store: rustls::RootCertStore) -> Result<String, String> {
    let config = rustls::ClientConfig::builder().with_root_certificates(store).with_no_client_auth();
    let server = host.to_string().try_into().map_err(|_| format!("{host} is not a server name"))?;
    let mut connection = rustls::ClientConnection::new(Arc::new(config), server).map_err(|e| e.to_string())?;
    let mut socket = TcpStream::connect((host, 443)).map_err(|e| format!("connect {host}:443: {e}"))?;
    let mut tls = rustls::Stream::new(&mut connection, &mut socket);
    // Writing forces the handshake to complete, so a validation failure
    // surfaces here rather than being deferred.
    tls.write_all(format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    let suite = connection
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()))
        .unwrap_or_else(|| "?".into());
    Ok(suite)
}

fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "example.com".to_string());

    match roots_from(BUNDLE).and_then(|store| handshake(&host, store)) {
        Ok(suite) => println!("PASS  {host} validated against the rendered store ({suite})"),
        Err(e) => {
            println!("FAIL  {host}: {e}");
            std::process::exit(1);
        }
    }

    // The negative control: an empty store must refuse the same server.
    // Without this the probe cannot distinguish a working trust store from
    // a client that never checked.
    match handshake(&host, rustls::RootCertStore::empty()) {
        Ok(_) => {
            println!("FAIL  {host} was accepted with an empty root store — nothing is being verified");
            std::process::exit(1);
        }
        Err(e) => println!("PASS  an empty root store refuses {host} ({})", e.lines().next().unwrap_or("")),
    }
}
