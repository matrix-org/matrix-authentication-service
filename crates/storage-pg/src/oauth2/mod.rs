// Copyright 2021-2023 The Matrix.org Foundation C.I.C.
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

//! A module containing the PostgreSQL implementations of the OAuth2-related
//! repositories

mod access_token;
mod authorization_grant;
mod client;
mod refresh_token;
mod session;

pub use self::{
    access_token::PgOAuth2AccessTokenRepository,
    authorization_grant::PgOAuth2AuthorizationGrantRepository, client::PgOAuth2ClientRepository,
    refresh_token::PgOAuth2RefreshTokenRepository, session::PgOAuth2SessionRepository,
};

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::AuthorizationCode;
    use mas_storage::{clock::MockClock, Clock, Pagination, Repository};
    use oauth2_types::{
        requests::{GrantType, ResponseMode},
        scope::{Scope, OPENID},
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_repositories(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Lookup a non-existing client
        let client = repo.oauth2_client().lookup(Ulid::nil()).await.unwrap();
        assert_eq!(client, None);

        // Find a non-existing client by client id
        let client = repo
            .oauth2_client()
            .find_by_client_id("some-client-id")
            .await
            .unwrap();
        assert_eq!(client, None);

        // Create a client
        let client = repo
            .oauth2_client()
            .add(
                &mut rng,
                &clock,
                vec!["https://example.com/redirect".parse().unwrap()],
                None,
                vec![GrantType::AuthorizationCode],
                Vec::new(), // TODO: contacts are not yet saved
                // vec!["contact@example.com".to_owned()],
                Some("Test client".to_owned()),
                Some("https://example.com/logo.png".parse().unwrap()),
                Some("https://example.com/".parse().unwrap()),
                Some("https://example.com/policy".parse().unwrap()),
                Some("https://example.com/tos".parse().unwrap()),
                Some("https://example.com/jwks.json".parse().unwrap()),
                None,
                None,
                None,
                None,
                None,
                Some("https://example.com/login".parse().unwrap()),
            )
            .await
            .unwrap();

        // Lookup the same client by id
        let client_lookup = repo
            .oauth2_client()
            .lookup(client.id)
            .await
            .unwrap()
            .expect("client not found");
        assert_eq!(client, client_lookup);

        // Find the same client by client id
        let client_lookup = repo
            .oauth2_client()
            .find_by_client_id(&client.client_id)
            .await
            .unwrap()
            .expect("client not found");
        assert_eq!(client, client_lookup);

        // Lookup a non-existing grant
        let grant = repo
            .oauth2_authorization_grant()
            .lookup(Ulid::nil())
            .await
            .unwrap();
        assert_eq!(grant, None);

        // Find a non-existing grant by code
        let grant = repo
            .oauth2_authorization_grant()
            .find_by_code("code")
            .await
            .unwrap();
        assert_eq!(grant, None);

        // Create an authorization grant
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut rng,
                &clock,
                &client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: "code".to_owned(),
                    pkce: None,
                }),
                Some("state".to_owned()),
                Some("nonce".to_owned()),
                None,
                ResponseMode::Query,
                true,
                false,
            )
            .await
            .unwrap();
        assert!(grant.is_pending());

        // Lookup the same grant by id
        let grant_lookup = repo
            .oauth2_authorization_grant()
            .lookup(grant.id)
            .await
            .unwrap()
            .expect("grant not found");
        assert_eq!(grant, grant_lookup);

        // Find the same grant by code
        let grant_lookup = repo
            .oauth2_authorization_grant()
            .find_by_code("code")
            .await
            .unwrap()
            .expect("grant not found");
        assert_eq!(grant, grant_lookup);

        // Create a user and a start a user session
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();
        let user_session = repo
            .browser_session()
            .add(&mut rng, &clock, &user)
            .await
            .unwrap();

        // Lookup the consent the user gave to the client
        let consent = repo
            .oauth2_client()
            .get_consent_for_user(&client, &user)
            .await
            .unwrap();
        assert!(consent.is_empty());

        // Give consent to the client
        let scope = Scope::from_iter([OPENID]);
        repo.oauth2_client()
            .give_consent_for_user(&mut rng, &clock, &client, &user, &scope)
            .await
            .unwrap();

        // Lookup the consent the user gave to the client
        let consent = repo
            .oauth2_client()
            .get_consent_for_user(&client, &user)
            .await
            .unwrap();
        assert_eq!(scope, consent);

        // Lookup a non-existing session
        let session = repo.oauth2_session().lookup(Ulid::nil()).await.unwrap();
        assert_eq!(session, None);

        // Create an OAuth session
        let session = repo
            .oauth2_session()
            .add(
                &mut rng,
                &clock,
                &client,
                &user_session,
                grant.scope.clone(),
            )
            .await
            .unwrap();

        // Mark the grant as fulfilled
        let grant = repo
            .oauth2_authorization_grant()
            .fulfill(&clock, &session, grant)
            .await
            .unwrap();
        assert!(grant.is_fulfilled());

        // Lookup the same session by id
        let session_lookup = repo
            .oauth2_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("session not found");
        assert_eq!(session, session_lookup);

        // Mark the grant as exchanged
        let grant = repo
            .oauth2_authorization_grant()
            .exchange(&clock, grant)
            .await
            .unwrap();
        assert!(grant.is_exchanged());

        // Lookup a non-existing token
        let token = repo
            .oauth2_access_token()
            .lookup(Ulid::nil())
            .await
            .unwrap();
        assert_eq!(token, None);

        // Find a non-existing token
        let token = repo
            .oauth2_access_token()
            .find_by_token("aabbcc")
            .await
            .unwrap();
        assert_eq!(token, None);

        // Create an access token
        let access_token = repo
            .oauth2_access_token()
            .add(
                &mut rng,
                &clock,
                &session,
                "aabbcc".to_owned(),
                Duration::minutes(5),
            )
            .await
            .unwrap();

        // Lookup the same token by id
        let access_token_lookup = repo
            .oauth2_access_token()
            .lookup(access_token.id)
            .await
            .unwrap()
            .expect("token not found");
        assert_eq!(access_token, access_token_lookup);

        // Find the same token by token
        let access_token_lookup = repo
            .oauth2_access_token()
            .find_by_token("aabbcc")
            .await
            .unwrap()
            .expect("token not found");
        assert_eq!(access_token, access_token_lookup);

        // Lookup a non-existing refresh token
        let refresh_token = repo
            .oauth2_refresh_token()
            .lookup(Ulid::nil())
            .await
            .unwrap();
        assert_eq!(refresh_token, None);

        // Find a non-existing refresh token
        let refresh_token = repo
            .oauth2_refresh_token()
            .find_by_token("aabbcc")
            .await
            .unwrap();
        assert_eq!(refresh_token, None);

        // Create a refresh token
        let refresh_token = repo
            .oauth2_refresh_token()
            .add(
                &mut rng,
                &clock,
                &session,
                &access_token,
                "aabbcc".to_owned(),
            )
            .await
            .unwrap();

        // Lookup the same refresh token by id
        let refresh_token_lookup = repo
            .oauth2_refresh_token()
            .lookup(refresh_token.id)
            .await
            .unwrap()
            .expect("refresh token not found");
        assert_eq!(refresh_token, refresh_token_lookup);

        // Find the same refresh token by token
        let refresh_token_lookup = repo
            .oauth2_refresh_token()
            .find_by_token("aabbcc")
            .await
            .unwrap()
            .expect("refresh token not found");
        assert_eq!(refresh_token, refresh_token_lookup);

        assert!(access_token.is_valid(clock.now()));
        clock.advance(Duration::minutes(6));
        assert!(!access_token.is_valid(clock.now()));

        // XXX: we might want to create a new access token
        clock.advance(Duration::minutes(-6)); // Go back in time
        assert!(access_token.is_valid(clock.now()));

        // Mark the access token as revoked
        let access_token = repo
            .oauth2_access_token()
            .revoke(&clock, access_token)
            .await
            .unwrap();
        assert!(!access_token.is_valid(clock.now()));

        // Mark the refresh token as consumed
        assert!(refresh_token.is_valid());
        let refresh_token = repo
            .oauth2_refresh_token()
            .consume(&clock, refresh_token)
            .await
            .unwrap();
        assert!(!refresh_token.is_valid());

        // Mark the session as finished
        assert!(session.is_valid());
        let session = repo.oauth2_session().finish(&clock, session).await.unwrap();
        assert!(!session.is_valid());

        // The session should appear in the paginated list of sessions for the user
        let sessions = repo
            .oauth2_session()
            .list_paginated(&user, Pagination::first(10))
            .await
            .unwrap();
        assert!(!sessions.has_next_page);
        assert_eq!(sessions.edges, vec![session]);
    }
}
