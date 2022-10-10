use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::X509;

pub struct CA {
    cert: X509,
    key: PKey<Private>,
}

impl CA {
    pub fn new(days_valid: u32) -> Result<Self, ErrorStack> {
        let key = Rsa::generate(4096)?;
        let public_key = PKey::public_key_from_pem(&key.public_key_to_pem()?)?;
        let private_key = PKey::from_rsa(key)?;

        let mut builder = X509::builder()?;

        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(days_valid)?.as_ref())?;
        builder.set_pubkey(public_key.as_ref())?;

        builder.sign(private_key.as_ref(), MessageDigest::sha512())?;
        let cert = builder.build();
        let ca = CA { cert, key: private_key };
        Ok(ca)
    }
}

#[cfg(test)]
mod test {
    use crate::ca::CA;

    #[test]
    fn create_ca() {
        let ca = CA::new(1).unwrap();
        println!("{:#?}", ca.cert);
    }
}