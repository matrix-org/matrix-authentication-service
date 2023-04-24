// Copyright 2022, 2023 The Matrix.org Foundation C.I.C.
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

//! A module containing PostgreSQL implementation of repositories for the
//! compatibility layer

mod access_token;
mod refresh_token;
mod session;
mod sso_login;

pub use self::{
    access_token::PgCompatAccessTokenRepository, refresh_token::PgCompatRefreshTokenRepository,
    session::PgCompatSessionRepository, sso_login::PgCompatSsoLoginRepository,
};

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::Device;
    use mas_storage::{
        clock::MockClock,
        compat::{
            CompatAccessTokenRepository, CompatRefreshTokenRepository, CompatSessionRepository,
        },
        user::UserRepository,
        Clock, Pagination, Repository, RepositoryAccess,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_session_repository(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let device_str = device.as_str().to_owned();
        let session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device)
            .await
            .unwrap();
        assert_eq!(session.user_id, user.id);
        assert_eq!(session.device.as_str(), device_str);
        assert!(session.is_valid());
        assert!(!session.is_finished());

        // Lookup the session and check it didn't change
        let session_lookup = repo
            .compat_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("compat session not found");
        assert_eq!(session_lookup.id, session.id);
        assert_eq!(session_lookup.user_id, user.id);
        assert_eq!(session_lookup.device.as_str(), device_str);
        assert!(session_lookup.is_valid());
        assert!(!session_lookup.is_finished());

        // Finish the session
        let session = repo.compat_session().finish(&clock, session).await.unwrap();
        assert!(!session.is_valid());
        assert!(session.is_finished());

        // Reload the session and check again
        let session_lookup = repo
            .compat_session()
            .lookup(session.id)
            .await
            .unwrap()
            .expect("compat session not found");
        assert!(!session_lookup.is_valid());
        assert!(session_lookup.is_finished());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_access_token_repository(pool: PgPool) {
        const FIRST_TOKEN: &str = "first_access_token";
        const SECOND_TOKEN: &str = "second_access_token";
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device)
            .await
            .unwrap();

        // Add an access token to that session
        let token = repo
            .compat_access_token()
            .add(
                &mut rng,
                &clock,
                &session,
                FIRST_TOKEN.to_owned(),
                Some(Duration::minutes(1)),
            )
            .await
            .unwrap();
        assert_eq!(token.session_id, session.id);
        assert_eq!(token.token, FIRST_TOKEN);

        // Commit the txn and grab a new transaction, to test a conflict
        repo.save().await.unwrap();

        {
            let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
            // Adding the same token a second time should conflict
            assert!(repo
                .compat_access_token()
                .add(
                    &mut rng,
                    &clock,
                    &session,
                    FIRST_TOKEN.to_owned(),
                    Some(Duration::minutes(1)),
                )
                .await
                .is_err());
            repo.cancel().await.unwrap();
        }

        // Grab a new repo
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Looking up via ID works
        let token_lookup = repo
            .compat_access_token()
            .lookup(token.id)
            .await
            .unwrap()
            .expect("compat access token not found");
        assert_eq!(token.id, token_lookup.id);
        assert_eq!(token_lookup.session_id, session.id);

        // Looking up via the token value works
        let token_lookup = repo
            .compat_access_token()
            .find_by_token(FIRST_TOKEN)
            .await
            .unwrap()
            .expect("compat access token not found");
        assert_eq!(token.id, token_lookup.id);
        assert_eq!(token_lookup.session_id, session.id);

        // Token is currently valid
        assert!(token.is_valid(clock.now()));

        clock.advance(Duration::minutes(1));
        // Token should have expired
        assert!(!token.is_valid(clock.now()));

        // Add a second access token, this time without expiration
        let token = repo
            .compat_access_token()
            .add(&mut rng, &clock, &session, SECOND_TOKEN.to_owned(), None)
            .await
            .unwrap();
        assert_eq!(token.session_id, session.id);
        assert_eq!(token.token, SECOND_TOKEN);

        // Token is currently valid
        assert!(token.is_valid(clock.now()));

        // Make it expire
        repo.compat_access_token()
            .expire(&clock, token)
            .await
            .unwrap();

        // Reload it
        let token = repo
            .compat_access_token()
            .find_by_token(SECOND_TOKEN)
            .await
            .unwrap()
            .expect("compat access token not found");

        // Token is not valid anymore
        assert!(!token.is_valid(clock.now()));

        repo.save().await.unwrap();
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_refresh_token_repository(pool: PgPool) {
        const ACCESS_TOKEN: &str = "access_token";
        const REFRESH_TOKEN: &str = "refresh_token";
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device)
            .await
            .unwrap();

        // Add an access token to that session
        let access_token = repo
            .compat_access_token()
            .add(&mut rng, &clock, &session, ACCESS_TOKEN.to_owned(), None)
            .await
            .unwrap();

        let refresh_token = repo
            .compat_refresh_token()
            .add(
                &mut rng,
                &clock,
                &session,
                &access_token,
                REFRESH_TOKEN.to_owned(),
            )
            .await
            .unwrap();
        assert_eq!(refresh_token.session_id, session.id);
        assert_eq!(refresh_token.access_token_id, access_token.id);
        assert_eq!(refresh_token.token, REFRESH_TOKEN);
        assert!(refresh_token.is_valid());
        assert!(!refresh_token.is_consumed());

        // Look it up by ID and check everything matches
        let refresh_token_lookup = repo
            .compat_refresh_token()
            .lookup(refresh_token.id)
            .await
            .unwrap()
            .expect("refresh token not found");
        assert_eq!(refresh_token_lookup.id, refresh_token.id);
        assert_eq!(refresh_token_lookup.session_id, session.id);
        assert_eq!(refresh_token_lookup.access_token_id, access_token.id);
        assert_eq!(refresh_token_lookup.token, REFRESH_TOKEN);
        assert!(refresh_token_lookup.is_valid());
        assert!(!refresh_token_lookup.is_consumed());

        // Look it up by token and check everything matches
        let refresh_token_lookup = repo
            .compat_refresh_token()
            .find_by_token(REFRESH_TOKEN)
            .await
            .unwrap()
            .expect("refresh token not found");
        assert_eq!(refresh_token_lookup.id, refresh_token.id);
        assert_eq!(refresh_token_lookup.session_id, session.id);
        assert_eq!(refresh_token_lookup.access_token_id, access_token.id);
        assert_eq!(refresh_token_lookup.token, REFRESH_TOKEN);
        assert!(refresh_token_lookup.is_valid());
        assert!(!refresh_token_lookup.is_consumed());

        // Consume it
        let refresh_token = repo
            .compat_refresh_token()
            .consume(&clock, refresh_token)
            .await
            .unwrap();
        assert!(!refresh_token.is_valid());
        assert!(refresh_token.is_consumed());

        // Reload it and check again
        let refresh_token_lookup = repo
            .compat_refresh_token()
            .find_by_token(REFRESH_TOKEN)
            .await
            .unwrap()
            .expect("refresh token not found");
        assert!(!refresh_token_lookup.is_valid());
        assert!(refresh_token_lookup.is_consumed());

        // Consuming it again should not work
        assert!(repo
            .compat_refresh_token()
            .consume(&clock, refresh_token)
            .await
            .is_err());

        repo.save().await.unwrap();
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_compat_sso_login_repository(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create a user
        let user = repo
            .user()
            .add(&mut rng, &clock, "john".to_owned())
            .await
            .unwrap();

        // Lookup an unknown SSO login
        let login = repo.compat_sso_login().lookup(Ulid::nil()).await.unwrap();
        assert_eq!(login, None);

        // Lookup an unknown login token
        let login = repo
            .compat_sso_login()
            .find_by_token("login-token")
            .await
            .unwrap();
        assert_eq!(login, None);

        // Start a new SSO login
        let login = repo
            .compat_sso_login()
            .add(
                &mut rng,
                &clock,
                "login-token".to_owned(),
                "https://example.com/callback".parse().unwrap(),
            )
            .await
            .unwrap();
        assert!(login.is_pending());

        // Lookup the login by ID
        let login_lookup = repo
            .compat_sso_login()
            .lookup(login.id)
            .await
            .unwrap()
            .expect("login not found");
        assert_eq!(login_lookup, login);

        // Find the login by token
        let login_lookup = repo
            .compat_sso_login()
            .find_by_token("login-token")
            .await
            .unwrap()
            .expect("login not found");
        assert_eq!(login_lookup, login);

        // Exchanging before fulfilling should not work
        // Note: It should also not poison the SQL transaction
        let res = repo
            .compat_sso_login()
            .exchange(&clock, login.clone())
            .await;
        assert!(res.is_err());

        // Start a compat session for that user
        let device = Device::generate(&mut rng);
        let session = repo
            .compat_session()
            .add(&mut rng, &clock, &user, device)
            .await
            .unwrap();

        // Associate the login with the session
        let login = repo
            .compat_sso_login()
            .fulfill(&clock, login, &session)
            .await
            .unwrap();
        assert!(login.is_fulfilled());

        // Fulfilling again should not work
        // Note: It should also not poison the SQL transaction
        let res = repo
            .compat_sso_login()
            .fulfill(&clock, login.clone(), &session)
            .await;
        assert!(res.is_err());

        // Exchange that login
        let login = repo
            .compat_sso_login()
            .exchange(&clock, login)
            .await
            .unwrap();
        assert!(login.is_exchanged());

        // Exchange again should not work
        // Note: It should also not poison the SQL transaction
        let res = repo
            .compat_sso_login()
            .exchange(&clock, login.clone())
            .await;
        assert!(res.is_err());

        // Fulfilling after exchanging should not work
        // Note: It should also not poison the SQL transaction
        let res = repo
            .compat_sso_login()
            .fulfill(&clock, login.clone(), &session)
            .await;
        assert!(res.is_err());

        // List the logins for the user
        let logins = repo
            .compat_sso_login()
            .list_paginated(&user, Pagination::first(10))
            .await
            .unwrap();
        assert!(!logins.has_next_page);
        assert_eq!(logins.edges, vec![login]);
    }
}
