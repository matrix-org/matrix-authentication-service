// Copyright 2023 The Matrix.org Foundation C.I.C.
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

use chrono::Duration;
use mas_storage::{
    clock::MockClock,
    user::{
        BrowserSessionFilter, BrowserSessionRepository, UserEmailFilter, UserEmailRepository,
        UserPasswordRepository, UserRepository,
    },
    Pagination, Repository, RepositoryAccess,
};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sqlx::PgPool;

use crate::PgRepository;

/// Test the user repository, by adding and looking up a user
#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_repo(pool: PgPool) {
    const USERNAME: &str = "john";

    let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    // Initially, the user shouldn't exist
    assert!(!repo.user().exists(USERNAME).await.unwrap());
    assert!(repo
        .user()
        .find_by_username(USERNAME)
        .await
        .unwrap()
        .is_none());

    // Adding the user should work
    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // And now it should exist
    assert!(repo.user().exists(USERNAME).await.unwrap());
    assert!(repo
        .user()
        .find_by_username(USERNAME)
        .await
        .unwrap()
        .is_some());
    assert!(repo.user().lookup(user.id).await.unwrap().is_some());

    // Adding a second time should give a conflict
    assert!(repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .is_err());

    repo.save().await.unwrap();
}

/// Test the user email repository, by trying out most of its methods
#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_email_repo(pool: PgPool) {
    const USERNAME: &str = "john";
    const CODE: &str = "012345";
    const CODE2: &str = "543210";
    const EMAIL: &str = "john@example.com";

    let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // The user email should not exist yet
    assert!(repo
        .user_email()
        .find(&user, EMAIL)
        .await
        .unwrap()
        .is_none());

    let all = UserEmailFilter::new().for_user(&user);
    let pending = all.pending_only();
    let verified = all.verified_only();

    // Check the counts
    assert_eq!(repo.user_email().count(all).await.unwrap(), 0);
    assert_eq!(repo.user_email().count(pending).await.unwrap(), 0);
    assert_eq!(repo.user_email().count(verified).await.unwrap(), 0);

    let user_email = repo
        .user_email()
        .add(&mut rng, &clock, &user, EMAIL.to_owned())
        .await
        .unwrap();

    assert_eq!(user_email.user_id, user.id);
    assert_eq!(user_email.email, EMAIL);
    assert!(user_email.confirmed_at.is_none());

    // Check the counts
    assert_eq!(repo.user_email().count(all).await.unwrap(), 1);
    assert_eq!(repo.user_email().count(pending).await.unwrap(), 1);
    assert_eq!(repo.user_email().count(verified).await.unwrap(), 0);

    assert!(repo
        .user_email()
        .find(&user, EMAIL)
        .await
        .unwrap()
        .is_some());

    let user_email = repo
        .user_email()
        .lookup(user_email.id)
        .await
        .unwrap()
        .expect("user email was not found");

    assert_eq!(user_email.user_id, user.id);
    assert_eq!(user_email.email, EMAIL);

    let verification = repo
        .user_email()
        .add_verification_code(
            &mut rng,
            &clock,
            &user_email,
            Duration::hours(8),
            CODE.to_owned(),
        )
        .await
        .unwrap();

    let verification_id = verification.id;
    assert_eq!(verification.user_email_id, user_email.id);
    assert_eq!(verification.code, CODE);

    // A single user email can have multiple verification at the same time
    let _verification2 = repo
        .user_email()
        .add_verification_code(
            &mut rng,
            &clock,
            &user_email,
            Duration::hours(8),
            CODE2.to_owned(),
        )
        .await
        .unwrap();

    let verification = repo
        .user_email()
        .find_verification_code(&clock, &user_email, CODE)
        .await
        .unwrap()
        .expect("user email verification was not found");

    assert_eq!(verification.id, verification_id);
    assert_eq!(verification.user_email_id, user_email.id);
    assert_eq!(verification.code, CODE);

    // Consuming the verification code
    repo.user_email()
        .consume_verification_code(&clock, verification)
        .await
        .unwrap();

    // Mark the email as verified
    repo.user_email()
        .mark_as_verified(&clock, user_email)
        .await
        .unwrap();

    // Check the counts
    assert_eq!(repo.user_email().count(all).await.unwrap(), 1);
    assert_eq!(repo.user_email().count(pending).await.unwrap(), 0);
    assert_eq!(repo.user_email().count(verified).await.unwrap(), 1);

    // Reload the user_email
    let user_email = repo
        .user_email()
        .find(&user, EMAIL)
        .await
        .unwrap()
        .expect("user email was not found");

    // The email should be marked as verified now
    assert!(user_email.confirmed_at.is_some());

    // Reload the verification
    let verification = repo
        .user_email()
        .find_verification_code(&clock, &user_email, CODE)
        .await
        .unwrap()
        .expect("user email verification was not found");

    // Consuming a second time should not work
    assert!(repo
        .user_email()
        .consume_verification_code(&clock, verification)
        .await
        .is_err());

    // The user shouldn't have a primary email yet
    assert!(repo
        .user_email()
        .get_primary(&user)
        .await
        .unwrap()
        .is_none());

    repo.user_email().set_as_primary(&user_email).await.unwrap();

    // Reload the user
    let user = repo
        .user()
        .lookup(user.id)
        .await
        .unwrap()
        .expect("user was not found");

    // Now it should have one
    assert!(repo
        .user_email()
        .get_primary(&user)
        .await
        .unwrap()
        .is_some());

    // Listing the user emails should work
    let emails = repo
        .user_email()
        .list(all, Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert_eq!(emails.edges.len(), 1);
    assert_eq!(emails.edges[0], user_email);

    let emails = repo
        .user_email()
        .list(verified, Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert_eq!(emails.edges.len(), 1);
    assert_eq!(emails.edges[0], user_email);

    let emails = repo
        .user_email()
        .list(pending, Pagination::first(10))
        .await
        .unwrap();
    assert!(!emails.has_next_page);
    assert!(emails.edges.is_empty());

    // Deleting the user email should work
    repo.user_email().remove(user_email).await.unwrap();
    assert_eq!(repo.user_email().count(all).await.unwrap(), 0);
    assert_eq!(repo.user_email().count(pending).await.unwrap(), 0);
    assert_eq!(repo.user_email().count(verified).await.unwrap(), 0);

    // Reload the user
    let user = repo
        .user()
        .lookup(user.id)
        .await
        .unwrap()
        .expect("user was not found");

    // The primary user email should be gone
    assert!(repo
        .user_email()
        .get_primary(&user)
        .await
        .unwrap()
        .is_none());

    repo.save().await.unwrap();
}

/// Test the user password repository implementation.
#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_password_repo(pool: PgPool) {
    const USERNAME: &str = "john";
    const FIRST_PASSWORD_HASH: &str = "doesntmatter";
    const SECOND_PASSWORD_HASH: &str = "alsodoesntmatter";

    let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    // User should have no active password
    assert!(repo.user_password().active(&user).await.unwrap().is_none());

    // Insert a first password
    let first_password = repo
        .user_password()
        .add(
            &mut rng,
            &clock,
            &user,
            1,
            FIRST_PASSWORD_HASH.to_owned(),
            None,
        )
        .await
        .unwrap();

    // User should now have an active password
    let first_password_lookup = repo
        .user_password()
        .active(&user)
        .await
        .unwrap()
        .expect("user should have an active password");

    assert_eq!(first_password.id, first_password_lookup.id);
    assert_eq!(first_password_lookup.hashed_password, FIRST_PASSWORD_HASH);
    assert_eq!(first_password_lookup.version, 1);
    assert_eq!(first_password_lookup.upgraded_from_id, None);

    // Getting the last inserted password is based on the clock, so we need to
    // advance it
    clock.advance(Duration::seconds(10));

    let second_password = repo
        .user_password()
        .add(
            &mut rng,
            &clock,
            &user,
            2,
            SECOND_PASSWORD_HASH.to_owned(),
            Some(&first_password),
        )
        .await
        .unwrap();

    // User should now have an active password
    let second_password_lookup = repo
        .user_password()
        .active(&user)
        .await
        .unwrap()
        .expect("user should have an active password");

    assert_eq!(second_password.id, second_password_lookup.id);
    assert_eq!(second_password_lookup.hashed_password, SECOND_PASSWORD_HASH);
    assert_eq!(second_password_lookup.version, 2);
    assert_eq!(
        second_password_lookup.upgraded_from_id,
        Some(first_password.id)
    );

    repo.save().await.unwrap();
}

#[sqlx::test(migrator = "crate::MIGRATOR")]
async fn test_user_session(pool: PgPool) {
    const USERNAME: &str = "john";

    let mut repo = PgRepository::from_pool(&pool).await.unwrap();
    let mut rng = ChaChaRng::seed_from_u64(42);
    let clock = MockClock::default();

    let user = repo
        .user()
        .add(&mut rng, &clock, USERNAME.to_owned())
        .await
        .unwrap();

    let all = BrowserSessionFilter::default().for_user(&user);
    let active = all.active_only();
    let finished = all.finished_only();

    assert_eq!(repo.browser_session().count(all).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 0);

    let session = repo
        .browser_session()
        .add(&mut rng, &clock, &user)
        .await
        .unwrap();
    assert_eq!(session.user.id, user.id);
    assert!(session.finished_at.is_none());

    assert_eq!(repo.browser_session().count(all).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 0);

    // The session should be in the list of active sessions
    let session_list = repo
        .browser_session()
        .list(active, Pagination::first(10))
        .await
        .unwrap();
    assert!(!session_list.has_next_page);
    assert_eq!(session_list.edges.len(), 1);
    assert_eq!(session_list.edges[0], session);

    let session_lookup = repo
        .browser_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("user session not found");

    assert_eq!(session_lookup.id, session.id);
    assert_eq!(session_lookup.user.id, user.id);
    assert!(session_lookup.finished_at.is_none());

    // Finish the session
    repo.browser_session()
        .finish(&clock, session_lookup)
        .await
        .unwrap();

    // The active session counter should be 0, and the finished one should be 1
    assert_eq!(repo.browser_session().count(all).await.unwrap(), 1);
    assert_eq!(repo.browser_session().count(active).await.unwrap(), 0);
    assert_eq!(repo.browser_session().count(finished).await.unwrap(), 1);

    // The session should not be in the list of active sessions anymore
    let session_list = repo
        .browser_session()
        .list(active, Pagination::first(10))
        .await
        .unwrap();
    assert!(!session_list.has_next_page);
    assert!(session_list.edges.is_empty());

    // Reload the session
    let session_lookup = repo
        .browser_session()
        .lookup(session.id)
        .await
        .unwrap()
        .expect("user session not found");

    assert_eq!(session_lookup.id, session.id);
    assert_eq!(session_lookup.user.id, user.id);
    // This time the session is finished
    assert!(session_lookup.finished_at.is_some());
}
