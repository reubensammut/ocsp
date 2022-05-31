extern crate rustls;
extern crate webpki_roots;
extern crate rand; 

//use std::fs::File;
use std::io::{Result, Write};
use std::net::TcpStream;
use std::sync::Arc;
use rand::Rng;

use rustls::{
    Certificate, ClientConfig, ClientConnection, OwnedTrustAnchor, RootCertStore, ServerName,
    Stream,
};
use sha1::{Sha1, Digest};
use x509_parser::der_parser::oid;
use x509_parser::prelude::ParsedExtension::{AuthorityInfoAccess,AuthorityKeyIdentifier};
use x509_parser::prelude::{AccessDescription, X509Certificate};
use x509_parser::prelude::GeneralName::URI;

fn get_ocsp_url(cert : &X509Certificate) -> String {
    let extensions = cert.extensions_map().unwrap(); 
    let auth_info_access = extensions.get(&oid!(1.3.6.1.5.5.7.1.1)).unwrap().parsed_extension();
    let auth_info_access : Option<Vec<&AccessDescription>> = match auth_info_access {
        AuthorityInfoAccess(a) => Some(a.accessdescs.as_slice().into_iter().filter(|x| {x.access_method == oid!(1.3.6.1.5.5.7.48.1)}).collect()),
        _ => None,
    };
    let ocsp_host = match auth_info_access.unwrap()[0].access_location
    {
        URI(u) => u,
        _ => ""
    };

    String::from(ocsp_host)
}

fn get_issuer_key_hash(cert : &X509Certificate) -> Vec<u8> {
    let extensions = cert.extensions_map().unwrap(); 
    let auth_key_id_ext = extensions.get(&oid!(2.5.29.35)).unwrap().parsed_extension();
    let key_id_wrapped = match auth_key_id_ext {
        AuthorityKeyIdentifier(a) => a.key_identifier.clone(),
        _ => None,
    };
    let key_id = key_id_wrapped.unwrap().0;
    
    Vec::from(key_id)
}

fn build_request(certs: &[Certificate]) -> (Vec<u8>,String) {
    let cert = x509_parser::parse_x509_certificate(&certs[0].0).unwrap().1;

    //File::create("cert.der").unwrap().write(&certs[0].0).unwrap();

    let mut hasher = Sha1::new();
    hasher.update(cert.issuer().as_raw());
    let issuer_name_hash = hasher.finalize().to_vec();

    let ocsp_host = get_ocsp_url(&cert);

    let serial = cert.tbs_certificate.raw_serial();

    let issuer_key_hash = get_issuer_key_hash(&cert);

    let rand_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let mut hasher = Sha1::new();
    hasher.update(&rand_bytes);
    let nonce = hasher.finalize().to_vec();

    let result = asn1::write(|w| {
        w.write_element(&asn1::SequenceWriter::new(&|w| { // OCSP
            w.write_element(&asn1::SequenceWriter::new(&|w| { // tbsRequest
                w.write_element(&asn1::SequenceWriter::new(&|w| { // requestList
                    w.write_element(&asn1::SequenceWriter::new(&|w| { // Request
                        w.write_element(&asn1::SequenceWriter::new(&|w| { // reqCert
                            w.write_element(&asn1::SequenceWriter::new(&|w| { // hashAlgorithm
                                w.write_element(&asn1::oid!(1,3,14,3,2,26));  // algorithm ID - sha 1
                                w.write_element(&());                         // parameters - null
                            }));
                            w.write_element(&issuer_name_hash.as_slice());    // issuer name hash
                            w.write_element(&issuer_key_hash.as_slice());     // issuer key hash
                            w.write_element(&asn1::BigInt::new(serial));      // serial
                        }));
                    }));
                }));
                w.write_explicit_element(&asn1::SequenceWriter::new(&|w| { // extensions
                    w.write_element(&asn1::SequenceWriter::new(&|w| {      // requestExtensions
                        w.write_element(&asn1::SequenceWriter::new(&|w| {  // Extension
                            w.write_element(&asn1::oid!(1,3,6,1,5,5,7,48,1,2));
                            w.write_element(&nonce.as_slice());
                        }));
                    }));
                }), 2);
            })); 
        }));
    });

    println!("{:?}", result);

    (result,ocsp_host)
}

fn make_ocsp_request(certs: &[Certificate]) {
    let (asn1_req,host) = build_request(certs);
    let client = reqwest::blocking::Client::new();
    let resp = client.post(host).header("Content-Type", "ocsp-request").body(asn1_req).send().unwrap().bytes().unwrap();

    println!("{:?}", resp.as_ref());
}

fn main() -> Result<()> {
    let mut stream = TcpStream::connect("google.com:443").unwrap();

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

    let server_name = ServerName::try_from("google.com").unwrap();

    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();

    let mut tls = Stream::new(&mut conn, &mut stream);

    tls.write(" ".as_bytes()).unwrap();

    tls.conn.send_close_notify();

    let certs = tls.conn.peer_certificates();

    match certs {
        None => println!("Domain has no certs"),
        Some(c) => make_ocsp_request(c),
    }

    Ok(())
}
