use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

mod config;
mod handlers;
mod state;
mod storage;

use self::config::Config;
use self::state::State;

#[async_std::main]
async fn main() -> tide::Result<()> {
    // Setup logging & tracing
    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter_layer =
        EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new("debug"))?;

    let subscriber = Registry::default().with(filter_layer).with(fmt_layer);
    subscriber.try_init()?;

    // Loading the config
    let config = Config::load()?;
    let address = config.listener.address.clone();
    // Create the shared state
    let state = State::new(config);

    // Start the server
    let mut app = tide::with_state(state);
    self::handlers::install(&mut app);
    app.listen(address).await?;
    Ok(())
}
