/* eslint-disable */
import * as types from "./graphql";
import { TypedDocumentNode as DocumentNode } from "@graphql-typed-document-node/core";

/**
 * Map of all GraphQL operations in the project.
 *
 * This map has several performance disadvantages:
 * 1. It is not tree-shakeable, so it will include all operations in the project.
 * 2. It is not minifiable, so the string of a GraphQL query will be multiple times inside the bundle.
 * 3. It does not support dead code elimination, so it will add unused operations.
 *
 * Therefore it is highly recommended to use the babel or swc plugin for production.
 */
const documents = {
  "\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n":
    types.AddEmailDocument,
  "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n":
    types.BrowserSession_SessionFragmentDoc,
  "\n  fragment BrowserSessionList_user on User {\n    browserSessions(first: $count, after: $cursor) {\n      edges {\n        cursor\n        node {\n          id\n          ...BrowserSession_session\n        }\n      }\n    }\n  }\n":
    types.BrowserSessionList_UserFragmentDoc,
  "\n  fragment CompatSsoLogin_login on CompatSsoLogin {\n    id\n    redirectUri\n    createdAt\n    session {\n      id\n      createdAt\n      deviceId\n      finishedAt\n    }\n  }\n":
    types.CompatSsoLogin_LoginFragmentDoc,
  "\n  fragment CompatSsoLoginList_user on User {\n    compatSsoLogins(first: $count, after: $cursor) {\n      edges {\n        node {\n          id\n          ...CompatSsoLogin_login\n        }\n      }\n    }\n  }\n":
    types.CompatSsoLoginList_UserFragmentDoc,
  "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n    }\n  }\n":
    types.OAuth2Session_SessionFragmentDoc,
  "\n  fragment OAuth2SessionList_user on User {\n    oauth2Sessions(first: $count, after: $cursor) {\n      edges {\n        cursor\n        node {\n          id\n          ...OAuth2Session_session\n        }\n      }\n    }\n  }\n":
    types.OAuth2SessionList_UserFragmentDoc,
  "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    createdAt\n    confirmedAt\n  }\n":
    types.UserEmail_EmailFragmentDoc,
  "\n  query UserEmailListQuery($userId: ID!, $first: Int!, $after: String) {\n    user(id: $userId) {\n      id\n      emails(first: $first, after: $after) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        pageInfo {\n          hasNextPage\n          endCursor\n        }\n      }\n    }\n  }\n":
    types.UserEmailListQueryDocument,
  "\n  query CurrentUserQuery {\n    viewer {\n      ... on User {\n        __typename\n        id\n      }\n    }\n  }\n":
    types.CurrentUserQueryDocument,
  "\n  query AccountQuery($id: ID!) {\n    user(id: $id) {\n      id\n      username\n    }\n  }\n":
    types.AccountQueryDocument,
  "\n  query BrowserSessionQuery($id: ID!) {\n    browserSession(id: $id) {\n      id\n      createdAt\n      lastAuthentication {\n        id\n        createdAt\n      }\n      user {\n        id\n        username\n      }\n    }\n  }\n":
    types.BrowserSessionQueryDocument,
  "\n  query HomeQuery($count: Int!, $cursor: String) {\n    # eslint-disable-next-line @graphql-eslint/no-deprecated\n    currentBrowserSession {\n      id\n      user {\n        id\n        username\n\n        ...CompatSsoLoginList_user\n        ...BrowserSessionList_user\n        ...OAuth2SessionList_user\n      }\n    }\n  }\n":
    types.HomeQueryDocument,
  "\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      id\n      clientId\n      clientName\n      clientUri\n      tosUri\n      policyUri\n      redirectUris\n    }\n  }\n":
    types.OAuth2ClientQueryDocument,
};

/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 *
 *
 * @example
 * ```ts
 * const query = graphql(`query GetUser($id: ID!) { user(id: $id) { name } }`);
 * ```
 *
 * The query argument is unknown!
 * Please regenerate the types.
 */
export function graphql(source: string): unknown;

/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"
): (typeof documents)["\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n"
): (typeof documents)["\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment BrowserSessionList_user on User {\n    browserSessions(first: $count, after: $cursor) {\n      edges {\n        cursor\n        node {\n          id\n          ...BrowserSession_session\n        }\n      }\n    }\n  }\n"
): (typeof documents)["\n  fragment BrowserSessionList_user on User {\n    browserSessions(first: $count, after: $cursor) {\n      edges {\n        cursor\n        node {\n          id\n          ...BrowserSession_session\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment CompatSsoLogin_login on CompatSsoLogin {\n    id\n    redirectUri\n    createdAt\n    session {\n      id\n      createdAt\n      deviceId\n      finishedAt\n    }\n  }\n"
): (typeof documents)["\n  fragment CompatSsoLogin_login on CompatSsoLogin {\n    id\n    redirectUri\n    createdAt\n    session {\n      id\n      createdAt\n      deviceId\n      finishedAt\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment CompatSsoLoginList_user on User {\n    compatSsoLogins(first: $count, after: $cursor) {\n      edges {\n        node {\n          id\n          ...CompatSsoLogin_login\n        }\n      }\n    }\n  }\n"
): (typeof documents)["\n  fragment CompatSsoLoginList_user on User {\n    compatSsoLogins(first: $count, after: $cursor) {\n      edges {\n        node {\n          id\n          ...CompatSsoLogin_login\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n    }\n  }\n"
): (typeof documents)["\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment OAuth2SessionList_user on User {\n    oauth2Sessions(first: $count, after: $cursor) {\n      edges {\n        cursor\n        node {\n          id\n          ...OAuth2Session_session\n        }\n      }\n    }\n  }\n"
): (typeof documents)["\n  fragment OAuth2SessionList_user on User {\n    oauth2Sessions(first: $count, after: $cursor) {\n      edges {\n        cursor\n        node {\n          id\n          ...OAuth2Session_session\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    createdAt\n    confirmedAt\n  }\n"
): (typeof documents)["\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    createdAt\n    confirmedAt\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query UserEmailListQuery($userId: ID!, $first: Int!, $after: String) {\n    user(id: $userId) {\n      id\n      emails(first: $first, after: $after) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        pageInfo {\n          hasNextPage\n          endCursor\n        }\n      }\n    }\n  }\n"
): (typeof documents)["\n  query UserEmailListQuery($userId: ID!, $first: Int!, $after: String) {\n    user(id: $userId) {\n      id\n      emails(first: $first, after: $after) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        pageInfo {\n          hasNextPage\n          endCursor\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query CurrentUserQuery {\n    viewer {\n      ... on User {\n        __typename\n        id\n      }\n    }\n  }\n"
): (typeof documents)["\n  query CurrentUserQuery {\n    viewer {\n      ... on User {\n        __typename\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query AccountQuery($id: ID!) {\n    user(id: $id) {\n      id\n      username\n    }\n  }\n"
): (typeof documents)["\n  query AccountQuery($id: ID!) {\n    user(id: $id) {\n      id\n      username\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query BrowserSessionQuery($id: ID!) {\n    browserSession(id: $id) {\n      id\n      createdAt\n      lastAuthentication {\n        id\n        createdAt\n      }\n      user {\n        id\n        username\n      }\n    }\n  }\n"
): (typeof documents)["\n  query BrowserSessionQuery($id: ID!) {\n    browserSession(id: $id) {\n      id\n      createdAt\n      lastAuthentication {\n        id\n        createdAt\n      }\n      user {\n        id\n        username\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query HomeQuery($count: Int!, $cursor: String) {\n    # eslint-disable-next-line @graphql-eslint/no-deprecated\n    currentBrowserSession {\n      id\n      user {\n        id\n        username\n\n        ...CompatSsoLoginList_user\n        ...BrowserSessionList_user\n        ...OAuth2SessionList_user\n      }\n    }\n  }\n"
): (typeof documents)["\n  query HomeQuery($count: Int!, $cursor: String) {\n    # eslint-disable-next-line @graphql-eslint/no-deprecated\n    currentBrowserSession {\n      id\n      user {\n        id\n        username\n\n        ...CompatSsoLoginList_user\n        ...BrowserSessionList_user\n        ...OAuth2SessionList_user\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      id\n      clientId\n      clientName\n      clientUri\n      tosUri\n      policyUri\n      redirectUris\n    }\n  }\n"
): (typeof documents)["\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      id\n      clientId\n      clientName\n      clientUri\n      tosUri\n      policyUri\n      redirectUris\n    }\n  }\n"];

export function graphql(source: string) {
  return (documents as any)[source] ?? {};
}

export type DocumentType<TDocumentNode extends DocumentNode<any, any>> =
  TDocumentNode extends DocumentNode<infer TType, any> ? TType : never;
