use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
use hyper::{Body, Response};
use hyper::service::{make_service_fn, service_fn};
use tracing::info;

pub async fn run() -> Result<(), Box<dyn Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    info!("Server listen at {}", addr);

    let make_svc = make_service_fn(|_| {
        async {
            Ok::<_, Infallible>(
                service_fn(|_| {
                    async {
                        Ok::<Response<Body>, Infallible>(Response::new(Body::from("Test")))
                    }
                })
            )
        }
    });

    axum::Server::bind(&addr).serve(make_svc).await?;
    Ok(())
}
