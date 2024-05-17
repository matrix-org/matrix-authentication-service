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

use async_graphql::{
    connection::{query, Connection, Edge, OpaqueCursor},
    Context, Object, ID,
};
use mas_storage::{upstream_oauth2::UpstreamOAuthProviderFilter, Pagination, RepositoryAccess};

use crate::graphql::{
    model::{
        Cursor, NodeCursor, NodeType, PreloadedTotalCount, UpstreamOAuth2Link,
        UpstreamOAuth2Provider,
    },
    state::ContextExt,
};

#[derive(Default)]
pub struct UpstreamOAuthQuery;

#[Object]
impl UpstreamOAuthQuery {
    /// Fetch an upstream OAuth 2.0 link by its ID.
    pub async fn upstream_oauth2_link(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<UpstreamOAuth2Link>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::UpstreamOAuth2Link.extract_ulid(&id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let link = repo.upstream_oauth_link().lookup(id).await?;
        repo.cancel().await?;

        let Some(link) = link else {
            return Ok(None);
        };

        if !requester.is_owner_or_admin(&link) {
            return Ok(None);
        }

        Ok(Some(UpstreamOAuth2Link::new(link)))
    }

    /// Fetch an upstream OAuth 2.0 provider by its ID.
    pub async fn upstream_oauth2_provider(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<UpstreamOAuth2Provider>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::UpstreamOAuth2Provider.extract_ulid(&id)?;

        let mut repo = state.repository().await?;
        let provider = repo.upstream_oauth_provider().lookup(id).await?;
        repo.cancel().await?;

        let Some(provider) = provider else {
            return Ok(None);
        };

        // We only allow enabled providers to be fetched
        if !provider.enabled() {
            return Ok(None);
        }

        Ok(Some(UpstreamOAuth2Provider::new(provider)))
    }

    /// Get a list of upstream OAuth 2.0 providers.
    async fn upstream_oauth2_providers(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UpstreamOAuth2Provider, PreloadedTotalCount>, async_graphql::Error>
    {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_type(NodeType::UpstreamOAuth2Provider)
                    })
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_type(NodeType::UpstreamOAuth2Provider)
                    })
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                // We only want enabled providers
                // XXX: we may want to let admins see disabled providers
                let filter = UpstreamOAuthProviderFilter::new().enabled_only();

                let page = repo
                    .upstream_oauth_provider()
                    .list(filter, pagination)
                    .await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.upstream_oauth_provider().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|p| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UpstreamOAuth2Provider, p.id)),
                        UpstreamOAuth2Provider::new(p),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}
