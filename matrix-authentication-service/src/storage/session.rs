use async_trait::async_trait;
use sqlx::{types::Json, PgPool};
use tide::sessions::{Session, SessionStore};
use tracing::{info_span, Instrument};

#[derive(Debug, Clone)]
struct SqlxSessionStore {
    pool: PgPool,
}

#[async_trait]
impl SessionStore for SqlxSessionStore {
    async fn load_session(&self, cookie_value: String) -> anyhow::Result<Option<Session>> {
        let id = Session::id_from_cookie_value(&cookie_value)?;
        let mut conn = self.pool.acquire().await?;

        let result: Option<(Json<Session>,)> = sqlx::query_as(
            r#"
                SELECT session
                FROM sessions
                WHERE id = $1
                  AND (expires IS NULL OR expires > $2)
            "#,
        )
        .bind(&id)
        .bind(chrono::Utc::now())
        .fetch_optional(&mut conn)
        .instrument(info_span!("Load session"))
        .await?;

        Ok(result.map(|(session,)| session.0))
    }

    async fn store_session(&self, session: Session) -> anyhow::Result<Option<String>> {
        let id = session.id();
        let expiry = session.expiry();
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            INSERT INTO sessions
              (id, session, expires) SELECT $1, $2, $3
            ON CONFLICT(id) DO UPDATE SET
              expires = EXCLUDED.expires,
              session = EXCLUDED.session
            "#,
        )
        .bind(&id)
        .bind(&Json(&session))
        .bind(&expiry)
        .execute(&mut conn)
        .instrument(info_span!("Store session"))
        .await?;

        Ok(session.into_cookie_value())
    }

    async fn destroy_session(&self, session: Session) -> anyhow::Result<()> {
        let id = session.id();
        let mut conn = self.pool.acquire().await?;

        sqlx::query(
            r#"
            DELETE FROM sessions WHERE id = $1
            "#,
        )
        .bind(&id)
        .execute(&mut conn)
        .instrument(info_span!("Destroy session"))
        .await?;

        Ok(())
    }

    async fn clear_store(&self) -> anyhow::Result<()> {
        let mut conn = self.pool.acquire().await?;
        sqlx::query("TRUNCATE sessions")
            .execute(&mut conn)
            .instrument(info_span!("Clear session store"))
            .await?;
        Ok(())
    }
}

impl super::Storage<PgPool> {
    pub fn session_store(&self) -> impl SessionStore {
        SqlxSessionStore {
            pool: self.pool().clone(),
        }
    }
}
