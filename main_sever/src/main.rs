use std::error::Error;
use futures_util::TryFutureExt;
use tracing::info;
use crate::ca::{CA, CAError};

mod logger;
mod web_server;
mod ca;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _guard = logger::init();
    info!("Starting server");

    let _ = load_ca().await?;

    web_server::run().await?;
    Ok(())
}

async fn load_ca() -> Result<CA, CAError> {
    const CA_DIR: &str = "./ssl/";
    const CA_DAYS_VALID: u32 = 10 * 365;

    let cert_path = format!("{}/ca.crt", CA_DIR);
    let key_path = format!("{}/ca.key", CA_DIR);

    info!("Loading CA");

    let ca = CA::load(&cert_path, &key_path)
        .or_else(|e| async {
            match &e {
                // TODO make better match
                CAError::OpenSslError(_) => Err(e),
                CAError::IOError(io_err) => match io_err.kind() {
                    std::io::ErrorKind::NotFound => {
                        info!("CA not found, creating new");
                        let _ = std::fs::create_dir_all(CA_DIR);
                        let ca = CA::new(CA_DAYS_VALID)?;
                        ca.save(&cert_path, &key_path).await?;
                        Ok(ca)
                    }
                    _ => Err(e),
                },
            }
        }).await?;
    info!("CA loaded");
    Ok(ca)
}
