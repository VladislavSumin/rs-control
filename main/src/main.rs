use std::error::Error;
use tracing::info;

mod logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    logger::init();
    info!("Starting server");
    Ok(())
}
