use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::x509::{X509Extension, X509Name, X509Req, X509};
use std::error::Error;
use std::io;
use std::fmt::{Debug, Display, Formatter};
use std::path::Path;
use futures_util::TryFutureExt;
use tokio::try_join;
use crate::ca::CAError::{IOError, OpenSslError};

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

    pub async fn load(cert: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<Self, CAError> {
        let cert = tokio::fs::read(cert.as_ref()).err_into()
            .and_then(|cert| async move { X509::from_pem(&cert).map_err(|e| { CAError::from(e) }) });

        let key = tokio::fs::read(key.as_ref()).err_into()
            .and_then(|key| async move { PKey::private_key_from_pem(&key).map_err(|e| { CAError::from(e) }) });

        let (cert, key) = try_join!(cert, key)?;

        let ca = CA { cert, key };

        Ok(ca)
    }

    pub async fn save(&self, cert: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<(), CAError> {
        let cert = tokio::fs::write(cert.as_ref(), self.cert.to_pem()?).err_into::<CAError>();
        let key = tokio::fs::write(key.as_ref(), self.key.private_key_to_pem_pkcs8()?).err_into();

        try_join!(cert, key)?;

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

    #[tokio::test]
    async fn save_load_ca() {
        const TEST_FOLDER: &str = "./test/ca/save_load_ca/";

        let cert_path = format!("{}/ca.crt", TEST_FOLDER);
        let key_path = format!("{}/ca.key", TEST_FOLDER);

        let _ = fs::remove_dir_all(TEST_FOLDER);
        fs::create_dir_all(TEST_FOLDER).unwrap();
        let original_ca = CA::new(1).unwrap();
        original_ca.save(&cert_path, &key_path).await.unwrap();
        let loaded_ca = CA::load(&cert_path, &key_path).await.unwrap();
        assert_eq!(original_ca.cert, loaded_ca.cert);
        fs::remove_dir_all(TEST_FOLDER).unwrap();
    }

    #[test]
    fn generate_simple_csr() {
        const TEST_DOMAIN: &str = "test.domain.vs";
        let (_csr, _key) = generate_csr(TEST_DOMAIN).unwrap();
    }
}
