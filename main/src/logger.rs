use tracing::Level;
use tracing_appender::rolling;
use tracing_subscriber::fmt;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::SubscriberExt;

pub fn init() {
    let info_log_layer = fmt::Layer::new()
        .with_writer(
            rolling::daily("./logs", "info")
                .with_max_level(Level::INFO)
        )
        .with_ansi(false);

    let debug_log_layer = fmt::Layer::new()
        .with_writer(rolling::daily("./logs", "debug"))
        .with_ansi(false);

    let std_log_layer = fmt::Layer::new()
        .with_writer(std::io::stdout.with_max_level(Level::DEBUG));

    let subscriber = tracing_subscriber::registry()
        .with(info_log_layer)
        .with(debug_log_layer)
        .with(std_log_layer);

    tracing::subscriber::set_global_default(subscriber).unwrap();
}
