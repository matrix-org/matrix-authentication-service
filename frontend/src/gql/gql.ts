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
  "\n  query CurrentViewerQuery {\n    viewer {\n      __typename\n      ... on User {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n":
    types.CurrentViewerQueryDocument,
  "\n  query CurrentViewerSessionQuery {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n":
    types.CurrentViewerSessionQueryDocument,
  "\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n":
    types.AddEmailDocument,
  "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n":
    types.BrowserSession_SessionFragmentDoc,
  "\n  query BrowserSessionList(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      browserSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          cursor\n          node {\n            id\n            ...BrowserSession_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n":
    types.BrowserSessionListDocument,
  "\n  fragment CompatSsoLogin_login on CompatSsoLogin {\n    id\n    redirectUri\n    createdAt\n    session {\n      id\n      createdAt\n      deviceId\n      finishedAt\n    }\n  }\n":
    types.CompatSsoLogin_LoginFragmentDoc,
  "\n  query CompatSsoLoginList(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      compatSsoLogins(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          node {\n            id\n            ...CompatSsoLogin_login\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n":
    types.CompatSsoLoginListDocument,
  "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n    }\n  }\n":
    types.OAuth2Session_SessionFragmentDoc,
  "\n  query OAuth2SessionListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      oauth2Sessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          cursor\n          node {\n            id\n            ...OAuth2Session_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n":
    types.OAuth2SessionListQueryDocument,
  "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    createdAt\n    confirmedAt\n  }\n":
    types.UserEmail_EmailFragmentDoc,
  "\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n":
    types.VerifyEmailDocument,
  "\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n":
    types.ResendVerificationEmailDocument,
  "\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n":
    types.UserEmailListQueryDocument,
  "\n  query UserPrimaryEmail($userId: ID!) {\n    user(id: $userId) {\n      id\n      primaryEmail {\n        id\n      }\n    }\n  }\n":
    types.UserPrimaryEmailDocument,
  "\n  query UserGreeting($userId: ID!) {\n    user(id: $userId) {\n      id\n      username\n    }\n  }\n":
    types.UserGreetingDocument,
  "\n  query BrowserSessionQuery($id: ID!) {\n    browserSession(id: $id) {\n      id\n      createdAt\n      lastAuthentication {\n        id\n        createdAt\n      }\n      user {\n        id\n        username\n      }\n    }\n  }\n":
    types.BrowserSessionQueryDocument,
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
  source: "\n  query CurrentViewerQuery {\n    viewer {\n      __typename\n      ... on User {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n"
): (typeof documents)["\n  query CurrentViewerQuery {\n    viewer {\n      __typename\n      ... on User {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query CurrentViewerSessionQuery {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n"
): (typeof documents)["\n  query CurrentViewerSessionQuery {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n"];
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
  source: "\n  query BrowserSessionList(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      browserSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          cursor\n          node {\n            id\n            ...BrowserSession_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"
): (typeof documents)["\n  query BrowserSessionList(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      browserSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          cursor\n          node {\n            id\n            ...BrowserSession_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"];
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
  source: "\n  query CompatSsoLoginList(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      compatSsoLogins(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          node {\n            id\n            ...CompatSsoLogin_login\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"
): (typeof documents)["\n  query CompatSsoLoginList(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      compatSsoLogins(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          node {\n            id\n            ...CompatSsoLogin_login\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"];
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
  source: "\n  query OAuth2SessionListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      oauth2Sessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          cursor\n          node {\n            id\n            ...OAuth2Session_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"
): (typeof documents)["\n  query OAuth2SessionListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      oauth2Sessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n      ) {\n        edges {\n          cursor\n          node {\n            id\n            ...OAuth2Session_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"];
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
  source: "\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"
): (typeof documents)["\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"
): (typeof documents)["\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"
): (typeof documents)["\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query UserPrimaryEmail($userId: ID!) {\n    user(id: $userId) {\n      id\n      primaryEmail {\n        id\n      }\n    }\n  }\n"
): (typeof documents)["\n  query UserPrimaryEmail($userId: ID!) {\n    user(id: $userId) {\n      id\n      primaryEmail {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query UserGreeting($userId: ID!) {\n    user(id: $userId) {\n      id\n      username\n    }\n  }\n"
): (typeof documents)["\n  query UserGreeting($userId: ID!) {\n    user(id: $userId) {\n      id\n      username\n    }\n  }\n"];
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
  source: "\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      id\n      clientId\n      clientName\n      clientUri\n      tosUri\n      policyUri\n      redirectUris\n    }\n  }\n"
): (typeof documents)["\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      id\n      clientId\n      clientName\n      clientUri\n      tosUri\n      policyUri\n      redirectUris\n    }\n  }\n"];

export function graphql(source: string) {
  return (documents as any)[source] ?? {};
}

export type DocumentType<TDocumentNode extends DocumentNode<any, any>> =
  TDocumentNode extends DocumentNode<infer TType, any> ? TType : never;
