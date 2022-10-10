use std::path::Path;
use rolling::Rotation;
use tracing::Level;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling;
use tracing_subscriber::fmt::format::{DefaultFields, Format};
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::fmt::writer::{MakeWriterExt, Tee, WithMaxLevel};
use tracing_subscriber::layer::SubscriberExt;

static LOG_DIR: &str = "./logs";

// Initialize tracer
//
// # Return
// vector of WorkerGuards, which protect file witter workers
pub fn init() -> Vec<WorkerGuard> {
    let (info_log_writer, info_guard) = create_file_writer("info", Level::INFO, Rotation::DAILY);
    let (debug_log_writer, debug_guard) = create_file_writer("debug", Level::INFO, Rotation::HOURLY);

    // we creating one layer for all file loggers, this make only one formatting call for all writers
    let file_layer = Layer::new().with_writer(Tee::new(info_log_writer, debug_log_writer))
        .with_ansi(false);

    // we can't use file_layer for std, because in std we use ansi and we need format this logs separately
    let std_log_layer = create_stream_layer(std::io::stdout, Level::DEBUG);

    let subscriber = tracing_subscriber::registry()
        .with(file_layer)
        .with(std_log_layer);

    tracing::subscriber::set_global_default(subscriber).unwrap();

    vec![info_guard, debug_guard]
}

fn create_stream_layer<T, F, W>(
    out: F,
    max_level: Level,
) -> Layer<T, DefaultFields, Format, WithMaxLevel<F>>
    where
        F: Fn() -> W + 'static,
        W: std::io::Write,
{
    Layer::new().with_writer(out.with_max_level(max_level))
}

fn create_file_writer(
    file_name_prefix: impl AsRef<Path>,
    max_level: Level,
    rotation: Rotation,
) -> (WithMaxLevel<NonBlocking>, WorkerGuard) {
    let sync_writer = rolling::RollingFileAppender::new(rotation, LOG_DIR, file_name_prefix);
    let (async_writer, guard) = tracing_appender::non_blocking(sync_writer);
    let async_writer = async_writer
        .with_max_level(max_level);

    (async_writer, guard)
}
