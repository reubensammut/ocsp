extern crate rustls;
extern crate webpki_roots;

use std::io::{Result, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::{
    Certificate, ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName,
    Stream,
};

fn handle_certs(certs: &[Certificate]) {
    let f = x509_parser::parse_x509_certificate(&certs[0].0).unwrap();

    println!("{:?}", f.1);
}

fn main() -> Result<()> {
    let mut stream = TcpStream::connect("docs.rs:443").unwrap();

    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = ServerName::try_from("docs.rs").unwrap();

    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();

    let mut tls = Stream::new(&mut conn, &mut stream);

    tls.write("".as_bytes()).unwrap();

    let certs = tls.conn.peer_certificates();

    match certs {
        None => println!("Domain has no certs"),
        Some(c) => handle_certs(c),
    }

    Ok(())
}
