use tera::Tera;
use tide::sessions::{MemoryStore, SessionMiddleware};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry};

mod config;
mod handlers;
mod state;
mod storage;
mod templates;

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

    // Load and compile the templates
    let templates = self::templates::load()?;

    // Setting up session store
    // TODO: persist somewhere
    let store = MemoryStore::new();

    // Create the shared state
    let state = State::new(config, templates);

    // Start the server
    let mut app = tide::with_state(state);

    app.with(SessionMiddleware::new(
        store,
        b"some random value that we will figure out later",
    ));

    app.with(tide::utils::Before(
        |mut request: tide::Request<_>| async move {
            let session = request.session_mut();
            let visits: usize = session.get("visits").unwrap_or_default();
            session.insert("visits", visits + 1).unwrap();
            request
        },
    ));

    self::handlers::install(&mut app);
    app.listen(address).await?;
    Ok(())
}
