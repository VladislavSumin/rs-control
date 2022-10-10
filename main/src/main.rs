use std::error::Error;
use tracing::info;

mod logger;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _guard = logger::init();
    info!("Starting server");
    Ok(())
}
