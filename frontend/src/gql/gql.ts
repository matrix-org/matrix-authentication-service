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
  "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n":
    types.BrowserSession_SessionFragmentDoc,
  "\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n        ...BrowserSession_session\n      }\n    }\n  }\n":
    types.EndBrowserSessionDocument,
  "\n  query BrowserSessionList(\n    $userId: ID!\n    $state: SessionState\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      browserSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n        state: $state\n      ) {\n        totalCount\n\n        edges {\n          cursor\n          node {\n            id\n            ...BrowserSession_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n":
    types.BrowserSessionListDocument,
  "\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n":
    types.OAuth2Client_DetailFragmentDoc,
  "\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n":
    types.CompatSession_SessionFragmentDoc,
  "\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n        finishedAt\n      }\n    }\n  }\n":
    types.EndCompatSessionDocument,
  "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      logoUri\n    }\n  }\n":
    types.OAuth2Session_SessionFragmentDoc,
  "\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n        ...OAuth2Session_session\n      }\n    }\n  }\n":
    types.EndOAuth2SessionDocument,
  "\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n":
    types.BrowserSession_DetailFragmentDoc,
  "\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n":
    types.CompatSession_DetailFragmentDoc,
  "\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n":
    types.OAuth2Session_DetailFragmentDoc,
  "\n  query SessionQuery($userId: ID!, $deviceId: String!) {\n    session(userId: $userId, deviceId: $deviceId) {\n      __typename\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n    }\n  }\n":
    types.SessionQueryDocument,
  "\n  fragment UnverifiedEmailAlert on User {\n    id\n    unverifiedEmails: emails(first: 0, state: PENDING) {\n      totalCount\n    }\n  }\n":
    types.UnverifiedEmailAlertFragmentDoc,
  "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    confirmedAt\n  }\n":
    types.UserEmail_EmailFragmentDoc,
  "\n  mutation RemoveEmail($id: ID!) {\n    removeEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n":
    types.RemoveEmailDocument,
  "\n  mutation SetPrimaryEmail($id: ID!) {\n    setPrimaryEmail(input: { userEmailId: $id }) {\n      status\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n    }\n  }\n":
    types.SetPrimaryEmailDocument,
  "\n  query UserGreeting($userId: ID!) {\n    user(id: $userId) {\n      id\n      username\n      matrix {\n        mxid\n        displayName\n      }\n\n      ...UnverifiedEmailAlert\n    }\n  }\n":
    types.UserGreetingDocument,
  "\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      violations\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n":
    types.AddEmailDocument,
  "\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n":
    types.UserEmailListQueryDocument,
  "\n  query UserPrimaryEmail($userId: ID!) {\n    user(id: $userId) {\n      id\n      primaryEmail {\n        id\n      }\n    }\n  }\n":
    types.UserPrimaryEmailDocument,
  "\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n      user {\n        id\n        matrix {\n          displayName\n        }\n      }\n    }\n  }\n":
    types.SetDisplayNameDocument,
  "\n  query AppSessionList(\n    $userId: ID!\n    $state: SessionState\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      appSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n        state: $state\n      ) {\n        totalCount\n\n        edges {\n          cursor\n          node {\n            __typename\n            ...CompatSession_session\n            ...OAuth2Session_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n":
    types.AppSessionListDocument,
  "\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n":
    types.BrowserSessionsOverview_UserFragmentDoc,
  "\n  fragment UserEmail_verifyEmail on UserEmail {\n    id\n    email\n  }\n":
    types.UserEmail_VerifyEmailFragmentDoc,
  "\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n":
    types.VerifyEmailDocument,
  "\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n":
    types.ResendVerificationEmailDocument,
  "\n  query BrowserSessionQuery($id: ID!) {\n    browserSession(id: $id) {\n      id\n      ...BrowserSession_detail\n    }\n  }\n":
    types.BrowserSessionQueryDocument,
  "\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n":
    types.OAuth2ClientQueryDocument,
  "\n  query SessionsOverviewQuery {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n":
    types.SessionsOverviewQueryDocument,
  "\n  query VerifyEmailQuery($id: ID!) {\n    userEmail(id: $id) {\n      ...UserEmail_verifyEmail\n    }\n  }\n":
    types.VerifyEmailQueryDocument,
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
  source: "\n  query CurrentViewerQuery {\n    viewer {\n      __typename\n      ... on User {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n",
): (typeof documents)["\n  query CurrentViewerQuery {\n    viewer {\n      __typename\n      ... on User {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query CurrentViewerSessionQuery {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n",
): (typeof documents)["\n  query CurrentViewerSessionQuery {\n    viewerSession {\n      __typename\n      ... on BrowserSession {\n        id\n      }\n\n      ... on Anonymous {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n",
): (typeof documents)["\n  fragment BrowserSession_session on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n        ...BrowserSession_session\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation EndBrowserSession($id: ID!) {\n    endBrowserSession(input: { browserSessionId: $id }) {\n      status\n      browserSession {\n        id\n        ...BrowserSession_session\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query BrowserSessionList(\n    $userId: ID!\n    $state: SessionState\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      browserSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n        state: $state\n      ) {\n        totalCount\n\n        edges {\n          cursor\n          node {\n            id\n            ...BrowserSession_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n",
): (typeof documents)["\n  query BrowserSessionList(\n    $userId: ID!\n    $state: SessionState\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      browserSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n        state: $state\n      ) {\n        totalCount\n\n        edges {\n          cursor\n          node {\n            id\n            ...BrowserSession_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n",
): (typeof documents)["\n  fragment OAuth2Client_detail on Oauth2Client {\n    id\n    clientId\n    clientName\n    clientUri\n    logoUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n",
): (typeof documents)["\n  fragment CompatSession_session on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n        finishedAt\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation EndCompatSession($id: ID!) {\n    endCompatSession(input: { compatSessionId: $id }) {\n      status\n      compatSession {\n        id\n        finishedAt\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      logoUri\n    }\n  }\n",
): (typeof documents)["\n  fragment OAuth2Session_session on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      logoUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n        ...OAuth2Session_session\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation EndOAuth2Session($id: ID!) {\n    endOauth2Session(input: { oauth2SessionId: $id }) {\n      status\n      oauth2Session {\n        id\n        ...OAuth2Session_session\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n",
): (typeof documents)["\n  fragment BrowserSession_detail on BrowserSession {\n    id\n    createdAt\n    finishedAt\n    userAgent\n    lastActiveIp\n    lastActiveAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n",
): (typeof documents)["\n  fragment CompatSession_detail on CompatSession {\n    id\n    createdAt\n    deviceId\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    ssoLogin {\n      id\n      redirectUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n",
): (typeof documents)["\n  fragment OAuth2Session_detail on Oauth2Session {\n    id\n    scope\n    createdAt\n    finishedAt\n    lastActiveIp\n    lastActiveAt\n    client {\n      id\n      clientId\n      clientName\n      clientUri\n      logoUri\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query SessionQuery($userId: ID!, $deviceId: String!) {\n    session(userId: $userId, deviceId: $deviceId) {\n      __typename\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n    }\n  }\n",
): (typeof documents)["\n  query SessionQuery($userId: ID!, $deviceId: String!) {\n    session(userId: $userId, deviceId: $deviceId) {\n      __typename\n      ...CompatSession_detail\n      ...OAuth2Session_detail\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment UnverifiedEmailAlert on User {\n    id\n    unverifiedEmails: emails(first: 0, state: PENDING) {\n      totalCount\n    }\n  }\n",
): (typeof documents)["\n  fragment UnverifiedEmailAlert on User {\n    id\n    unverifiedEmails: emails(first: 0, state: PENDING) {\n      totalCount\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    confirmedAt\n  }\n",
): (typeof documents)["\n  fragment UserEmail_email on UserEmail {\n    id\n    email\n    confirmedAt\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation RemoveEmail($id: ID!) {\n    removeEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation RemoveEmail($id: ID!) {\n    removeEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation SetPrimaryEmail($id: ID!) {\n    setPrimaryEmail(input: { userEmailId: $id }) {\n      status\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation SetPrimaryEmail($id: ID!) {\n    setPrimaryEmail(input: { userEmailId: $id }) {\n      status\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query UserGreeting($userId: ID!) {\n    user(id: $userId) {\n      id\n      username\n      matrix {\n        mxid\n        displayName\n      }\n\n      ...UnverifiedEmailAlert\n    }\n  }\n",
): (typeof documents)["\n  query UserGreeting($userId: ID!) {\n    user(id: $userId) {\n      id\n      username\n      matrix {\n        mxid\n        displayName\n      }\n\n      ...UnverifiedEmailAlert\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      violations\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation AddEmail($userId: ID!, $email: String!) {\n    addEmail(input: { userId: $userId, email: $email }) {\n      status\n      violations\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n",
): (typeof documents)["\n  query UserEmailListQuery(\n    $userId: ID!\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n\n      emails(first: $first, after: $after, last: $last, before: $before) {\n        edges {\n          cursor\n          node {\n            id\n            ...UserEmail_email\n          }\n        }\n        totalCount\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query UserPrimaryEmail($userId: ID!) {\n    user(id: $userId) {\n      id\n      primaryEmail {\n        id\n      }\n    }\n  }\n",
): (typeof documents)["\n  query UserPrimaryEmail($userId: ID!) {\n    user(id: $userId) {\n      id\n      primaryEmail {\n        id\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n      user {\n        id\n        matrix {\n          displayName\n        }\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation SetDisplayName($userId: ID!, $displayName: String) {\n    setDisplayName(input: { userId: $userId, displayName: $displayName }) {\n      status\n      user {\n        id\n        matrix {\n          displayName\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query AppSessionList(\n    $userId: ID!\n    $state: SessionState\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      appSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n        state: $state\n      ) {\n        totalCount\n\n        edges {\n          cursor\n          node {\n            __typename\n            ...CompatSession_session\n            ...OAuth2Session_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n",
): (typeof documents)["\n  query AppSessionList(\n    $userId: ID!\n    $state: SessionState\n    $first: Int\n    $after: String\n    $last: Int\n    $before: String\n  ) {\n    user(id: $userId) {\n      id\n      appSessions(\n        first: $first\n        after: $after\n        last: $last\n        before: $before\n        state: $state\n      ) {\n        totalCount\n\n        edges {\n          cursor\n          node {\n            __typename\n            ...CompatSession_session\n            ...OAuth2Session_session\n          }\n        }\n\n        pageInfo {\n          hasNextPage\n          hasPreviousPage\n          startCursor\n          endCursor\n        }\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n",
): (typeof documents)["\n  fragment BrowserSessionsOverview_user on User {\n    id\n\n    browserSessions(first: 0, state: ACTIVE) {\n      totalCount\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  fragment UserEmail_verifyEmail on UserEmail {\n    id\n    email\n  }\n",
): (typeof documents)["\n  fragment UserEmail_verifyEmail on UserEmail {\n    id\n    email\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation VerifyEmail($id: ID!, $code: String!) {\n    verifyEmail(input: { userEmailId: $id, code: $code }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n",
): (typeof documents)["\n  mutation ResendVerificationEmail($id: ID!) {\n    sendVerificationEmail(input: { userEmailId: $id }) {\n      status\n\n      user {\n        id\n        primaryEmail {\n          id\n        }\n      }\n\n      email {\n        id\n        ...UserEmail_email\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query BrowserSessionQuery($id: ID!) {\n    browserSession(id: $id) {\n      id\n      ...BrowserSession_detail\n    }\n  }\n",
): (typeof documents)["\n  query BrowserSessionQuery($id: ID!) {\n    browserSession(id: $id) {\n      id\n      ...BrowserSession_detail\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n",
): (typeof documents)["\n  query OAuth2ClientQuery($id: ID!) {\n    oauth2Client(id: $id) {\n      ...OAuth2Client_detail\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query SessionsOverviewQuery {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n",
): (typeof documents)["\n  query SessionsOverviewQuery {\n    viewer {\n      __typename\n\n      ... on User {\n        id\n        ...BrowserSessionsOverview_user\n      }\n    }\n  }\n"];
/**
 * The graphql function is used to parse GraphQL queries into a document that can be used by GraphQL clients.
 */
export function graphql(
  source: "\n  query VerifyEmailQuery($id: ID!) {\n    userEmail(id: $id) {\n      ...UserEmail_verifyEmail\n    }\n  }\n",
): (typeof documents)["\n  query VerifyEmailQuery($id: ID!) {\n    userEmail(id: $id) {\n      ...UserEmail_verifyEmail\n    }\n  }\n"];

export function graphql(source: string) {
  return (documents as any)[source] ?? {};
}

export type DocumentType<TDocumentNode extends DocumentNode<any, any>> =
  TDocumentNode extends DocumentNode<infer TType, any> ? TType : never;
