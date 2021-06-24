use tera::{Context, Tera};
use tide::Request;
use tracing::info;

use crate::state::State;

pub fn load() -> Result<Tera, tera::Error> {
    let path = format!("{}/templates/**/*.html", env!("CARGO_MANIFEST_DIR"));
    info!(%path, "Loading templates");
    Tera::new(&path)
}

pub async fn common_context(req: &Request<State>) -> Result<Context, anyhow::Error> {
    let state = req.state();
    let session = req.session();

    let mut ctx = Context::new();

    let visits: usize = session.get("visits").unwrap_or_default();
    ctx.insert("visits", &visits);

    let user: Option<String> = session.get("current_user");
    if let Some(ref user) = user {
        let user = state.storage().lookup_user(user).await?;
        ctx.insert("current_user", &user);
    }

    Ok(ctx)
}
