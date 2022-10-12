use std::error::Error;
use tracing::info;

mod logger;
mod web_server;
mod ca;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _guard = logger::init();
    info!("Starting server");
    web_server::run().await?;
    Ok(())
}
