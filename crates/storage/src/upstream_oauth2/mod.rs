// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod link;
mod provider;
mod session;

pub use self::{
    link::{PgUpstreamOAuthLinkRepository, UpstreamOAuthLinkRepository},
    provider::{PgUpstreamOAuthProviderRepository, UpstreamOAuthProviderRepository},
    session::{PgUpstreamOAuthSessionRepository, UpstreamOAuthSessionRepository},
};

#[cfg(test)]
mod tests {
    use oauth2_types::scope::{Scope, OPENID};
    use rand::SeedableRng;
    use sqlx::PgPool;

    use super::*;
    use crate::{user::UserRepository, Clock, Pagination, PgRepository, Repository};

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_repository(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let clock = Clock::mock();
        let mut repo = PgRepository::from_pool(&pool).await?;

        // The provider list should be empty at the start
        let all_providers = repo.upstream_oauth_provider().all().await?;
        assert!(all_providers.is_empty());

        // Let's add a provider
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &clock,
                "https://example.com/".to_owned(),
                Scope::from_iter([OPENID]),
                mas_iana::oauth::OAuthClientAuthenticationMethod::None,
                None,
                "client-id".to_owned(),
                None,
            )
            .await?;

        // Look it up in the database
        let provider = repo
            .upstream_oauth_provider()
            .lookup(provider.id)
            .await?
            .expect("provider to be found in the database");
        assert_eq!(provider.issuer, "https://example.com/");
        assert_eq!(provider.client_id, "client-id");

        // Start a session
        let session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &clock,
                &provider,
                "some-state".to_owned(),
                None,
                "some-nonce".to_owned(),
            )
            .await?;

        // Look it up in the database
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await?
            .expect("session to be found in the database");
        assert_eq!(session.provider_id, provider.id);
        assert_eq!(session.link_id(), None);
        assert!(session.is_pending());
        assert!(!session.is_completed());
        assert!(!session.is_consumed());

        // Create a link
        let link = repo
            .upstream_oauth_link()
            .add(&mut rng, &clock, &provider, "a-subject".to_owned())
            .await?;

        // We can look it up by its ID
        repo.upstream_oauth_link()
            .lookup(link.id)
            .await?
            .expect("link to be found in database");

        // or by its subject
        let link = repo
            .upstream_oauth_link()
            .find_by_subject(&provider, "a-subject")
            .await?
            .expect("link to be found in database");
        assert_eq!(link.subject, "a-subject");
        assert_eq!(link.provider_id, provider.id);

        let session = repo
            .upstream_oauth_session()
            .complete_with_link(&clock, session, &link, None)
            .await?;
        // Reload the session
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await?
            .expect("session to be found in the database");
        assert!(session.is_completed());
        assert!(!session.is_consumed());
        assert_eq!(session.link_id(), Some(link.id));

        let session = repo
            .upstream_oauth_session()
            .consume(&clock, session)
            .await?;
        // Reload the session
        let session = repo
            .upstream_oauth_session()
            .lookup(session.id)
            .await?
            .expect("session to be found in the database");
        assert!(session.is_consumed());

        let user = repo.user().add(&mut rng, &clock, "john".to_owned()).await?;
        repo.upstream_oauth_link()
            .associate_to_user(&link, &user)
            .await?;

        let links = repo
            .upstream_oauth_link()
            .list_paginated(&user, &Pagination::first(10))
            .await?;
        assert!(!links.has_previous_page);
        assert!(!links.has_next_page);
        assert_eq!(links.edges.len(), 1);
        assert_eq!(links.edges[0].id, link.id);
        assert_eq!(links.edges[0].user_id, Some(user.id));

        Ok(())
    }
}
