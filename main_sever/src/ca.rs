use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::x509::{X509Extension, X509Name, X509Req, X509};
use std::error::Error;
use std::{fs, io};
use std::fmt::{Debug, Display, Formatter};
use std::path::Path;
use crate::ca::CAError::{IOError, OpenSslError};

const CERT_SUB_PATH: &str = "ca.crt";
const KEY_SUB_PATH: &str = "ca.key";

#[derive(Debug)]
pub struct CA {
    cert: X509,
    key: PKey<Private>,
}

#[derive(Debug)]
pub enum CAError {
    OpenSslError(ErrorStack),
    IOError(io::Error),
}

impl From<ErrorStack> for CAError {
    fn from(es: ErrorStack) -> Self {
        OpenSslError(es)
    }
}

impl From<io::Error> for CAError {
    fn from(e: io::Error) -> Self {
        IOError(e)
    }
}

impl Display for CAError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for CAError {}

impl CA {
    pub fn new(days_valid: u32) -> Result<Self, CAError> {
        let (private_key, public_key) = generate_key()?;

        let mut builder = X509::builder()?;

        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(days_valid)?.as_ref())?;
        builder.set_pubkey(public_key.as_ref())?;

        builder.sign(private_key.as_ref(), MessageDigest::sha512())?;
        let cert = builder.build();
        let ca = CA { cert, key: private_key };
        Ok(ca)
    }

    pub fn load(dir: impl AsRef<Path>) -> Result<Self, CAError> {
        let dir = dir.as_ref();
        let cert = X509::from_pem(&fs::read(dir.join(CERT_SUB_PATH))?)?;
        let key = PKey::private_key_from_pem(&fs::read(dir.join(KEY_SUB_PATH))?)?;

        let ca = CA { cert, key };

        Ok(ca)
    }

    pub fn save(&self, dir: impl AsRef<Path>) -> Result<(), CAError> {
        let dir = dir.as_ref();

        fs::write(dir.join(CERT_SUB_PATH), self.cert.to_pem()?)?;
        fs::write(dir.join(KEY_SUB_PATH), self.key.private_key_to_pem_pkcs8()?)?;

        Ok(())
    }
}

fn generate_csr(dns_name: &str) -> Result<(X509Req, PKey<Private>), ErrorStack> {
    let mut req = X509Req::builder().unwrap();

    let mut name_builder = X509Name::builder().unwrap();
    name_builder.append_entry_by_text("CN", dns_name).unwrap();
    req.set_subject_name(&name_builder.build()).unwrap();

    let mut extensions = openssl::stack::Stack::new()?;
    extensions.push(X509Extension::new(
        None,
        Some(&req.x509v3_context(None)),
        "subjectAltName",
        &format!("DNS:{}", dns_name),
    )?)?;
    req.add_extensions(&extensions)?;
    req.set_version(2)?;

    let (private_key, public_key) = generate_key()?;
    req.set_pubkey(&public_key).unwrap();

    Ok((req.build(), private_key))
}

fn generate_key() -> Result<(PKey<Private>, PKey<Public>), ErrorStack> {
    let key = Rsa::generate(4096)?;
    let public_key = PKey::public_key_from_pem(&key.public_key_to_pem()?)?;
    let private_key = PKey::from_rsa(key)?;

    Ok((private_key, public_key))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::fs;

    #[test]
    fn create_ca() {
        let ca = CA::new(1).unwrap();
        println!("CA: {:#?}", ca);
    }

    #[test]
    fn save_load_ca() {
        const TEST_FOLDER: &str = "./test/ca/save_load_ca/";
        let _ = fs::remove_dir_all(TEST_FOLDER);
        fs::create_dir_all(TEST_FOLDER).unwrap();
        let original_ca = CA::new(1).unwrap();
        original_ca.save(TEST_FOLDER).unwrap();
        let loaded_ca = CA::load(TEST_FOLDER).unwrap();
        assert_eq!(original_ca.cert, loaded_ca.cert);
        fs::remove_dir_all(TEST_FOLDER).unwrap();
    }

    #[test]
    fn generate_simple_csr() {
        const TEST_DOMAIN: &str = "test.domain.vs";
        let (_csr, _key) = generate_csr(TEST_DOMAIN).unwrap();
    }
}
