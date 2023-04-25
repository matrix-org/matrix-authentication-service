/* eslint-disable */
import { TypedDocumentNode as DocumentNode } from '@graphql-typed-document-node/core';
export type Maybe<T> = T | null;
export type InputMaybe<T> = Maybe<T>;
export type Exact<T extends { [key: string]: unknown }> = { [K in keyof T]: T[K] };
export type MakeOptional<T, K extends keyof T> = Omit<T, K> & { [SubKey in K]?: Maybe<T[SubKey]> };
export type MakeMaybe<T, K extends keyof T> = Omit<T, K> & { [SubKey in K]: Maybe<T[SubKey]> };
/** All built-in and custom scalars, mapped to their actual values */
export type Scalars = {
  ID: string;
  String: string;
  Boolean: boolean;
  Int: number;
  Float: number;
  /**
   * Implement the DateTime<Utc> scalar
   *
   * The input/output is a string in RFC3339 format.
   */
  DateTime: any;
  /** URL is a String implementing the [URL Standard](http://url.spec.whatwg.org/) */
  Url: any;
};

/** The input for the `addEmail` mutation */
export type AddEmailInput = {
  /** The email address to add */
  email: Scalars['String'];
  /** The ID of the user to add the email address to */
  userId: Scalars['ID'];
};

/** The payload of the `addEmail` mutation */
export type AddEmailPayload = {
  __typename?: 'AddEmailPayload';
  /** The email address that was added */
  email: UserEmail;
  /** Status of the operation */
  status: AddEmailStatus;
  /** The user to whom the email address was added */
  user: User;
};

/** The status of the `addEmail` mutation */
export enum AddEmailStatus {
  /** The email address was added */
  Added = 'ADDED',
  /** The email address already exists */
  Exists = 'EXISTS'
}

export type Anonymous = Node & {
  __typename?: 'Anonymous';
  id: Scalars['ID'];
};

/**
 * An authentication records when a user enter their credential in a browser
 * session.
 */
export type Authentication = CreationEvent & Node & {
  __typename?: 'Authentication';
  /** When the object was created. */
  createdAt: Scalars['DateTime'];
  /** ID of the object. */
  id: Scalars['ID'];
};

/** A browser session represents a logged in user in a browser. */
export type BrowserSession = CreationEvent & Node & {
  __typename?: 'BrowserSession';
  /** When the object was created. */
  createdAt: Scalars['DateTime'];
  /** ID of the object. */
  id: Scalars['ID'];
  /** The most recent authentication of this session. */
  lastAuthentication?: Maybe<Authentication>;
  /** The user logged in this session. */
  user: User;
};

export type BrowserSessionConnection = {
  __typename?: 'BrowserSessionConnection';
  /** A list of edges. */
  edges: Array<BrowserSessionEdge>;
  /** A list of nodes. */
  nodes: Array<BrowserSession>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
};

/** An edge in a connection. */
export type BrowserSessionEdge = {
  __typename?: 'BrowserSessionEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String'];
  /** The item at the end of the edge */
  node: BrowserSession;
};

/**
 * A compat session represents a client session which used the legacy Matrix
 * login API.
 */
export type CompatSession = CreationEvent & Node & {
  __typename?: 'CompatSession';
  /** When the object was created. */
  createdAt: Scalars['DateTime'];
  /** The Matrix Device ID of this session. */
  deviceId: Scalars['String'];
  /** When the session ended. */
  finishedAt?: Maybe<Scalars['DateTime']>;
  /** ID of the object. */
  id: Scalars['ID'];
  /** The user authorized for this session. */
  user: User;
};

/**
 * A compat SSO login represents a login done through the legacy Matrix login
 * API, via the `m.login.sso` login method.
 */
export type CompatSsoLogin = Node & {
  __typename?: 'CompatSsoLogin';
  /** When the object was created. */
  createdAt: Scalars['DateTime'];
  /** When the client exchanged the login token sent during the redirection. */
  exchangedAt?: Maybe<Scalars['DateTime']>;
  /**
   * When the login was fulfilled, and the user was redirected back to the
   * client.
   */
  fulfilledAt?: Maybe<Scalars['DateTime']>;
  /** ID of the object. */
  id: Scalars['ID'];
  /** The redirect URI used during the login. */
  redirectUri: Scalars['Url'];
  /** The compat session which was started by this login. */
  session?: Maybe<CompatSession>;
};

export type CompatSsoLoginConnection = {
  __typename?: 'CompatSsoLoginConnection';
  /** A list of edges. */
  edges: Array<CompatSsoLoginEdge>;
  /** A list of nodes. */
  nodes: Array<CompatSsoLogin>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
};

/** An edge in a connection. */
export type CompatSsoLoginEdge = {
  __typename?: 'CompatSsoLoginEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String'];
  /** The item at the end of the edge */
  node: CompatSsoLogin;
};

/** An object with a creation date. */
export type CreationEvent = {
  /** When the object was created. */
  createdAt: Scalars['DateTime'];
};

/** The mutations root of the GraphQL interface. */
export type Mutation = {
  __typename?: 'Mutation';
  /** Add an email address to the specified user */
  addEmail: AddEmailPayload;
  /** Send a verification code for an email address */
  sendVerificationEmail: SendVerificationEmailPayload;
  /** Submit a verification code for an email address */
  verifyEmail: VerifyEmailPayload;
};


/** The mutations root of the GraphQL interface. */
export type MutationAddEmailArgs = {
  input: AddEmailInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationSendVerificationEmailArgs = {
  input: SendVerificationEmailInput;
};


/** The mutations root of the GraphQL interface. */
export type MutationVerifyEmailArgs = {
  input: VerifyEmailInput;
};

/** An object with an ID. */
export type Node = {
  /** ID of the object. */
  id: Scalars['ID'];
};

/** An OAuth 2.0 client */
export type Oauth2Client = Node & {
  __typename?: 'Oauth2Client';
  /** OAuth 2.0 client ID */
  clientId: Scalars['String'];
  /** Client name advertised by the client. */
  clientName?: Maybe<Scalars['String']>;
  /** Client URI advertised by the client. */
  clientUri?: Maybe<Scalars['Url']>;
  /** ID of the object. */
  id: Scalars['ID'];
  /** Privacy policy URI advertised by the client. */
  policyUri?: Maybe<Scalars['Url']>;
  /** List of redirect URIs used for authorization grants by the client. */
  redirectUris: Array<Scalars['Url']>;
  /** Terms of services URI advertised by the client. */
  tosUri?: Maybe<Scalars['Url']>;
};

/**
 * An OAuth 2.0 session represents a client session which used the OAuth APIs
 * to login.
 */
export type Oauth2Session = Node & {
  __typename?: 'Oauth2Session';
  /** The browser session which started this OAuth 2.0 session. */
  browserSession: BrowserSession;
  /** OAuth 2.0 client used by this session. */
  client: Oauth2Client;
  /** ID of the object. */
  id: Scalars['ID'];
  /** Scope granted for this session. */
  scope: Scalars['String'];
  /** User authorized for this session. */
  user: User;
};

export type Oauth2SessionConnection = {
  __typename?: 'Oauth2SessionConnection';
  /** A list of edges. */
  edges: Array<Oauth2SessionEdge>;
  /** A list of nodes. */
  nodes: Array<Oauth2Session>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
};

/** An edge in a connection. */
export type Oauth2SessionEdge = {
  __typename?: 'Oauth2SessionEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String'];
  /** The item at the end of the edge */
  node: Oauth2Session;
};

/** Information about pagination in a connection */
export type PageInfo = {
  __typename?: 'PageInfo';
  /** When paginating forwards, the cursor to continue. */
  endCursor?: Maybe<Scalars['String']>;
  /** When paginating forwards, are there more items? */
  hasNextPage: Scalars['Boolean'];
  /** When paginating backwards, are there more items? */
  hasPreviousPage: Scalars['Boolean'];
  /** When paginating backwards, the cursor to continue. */
  startCursor?: Maybe<Scalars['String']>;
};

/** The query root of the GraphQL interface. */
export type Query = {
  __typename?: 'Query';
  /** Fetch a browser session by its ID. */
  browserSession?: Maybe<BrowserSession>;
  /**
   * Get the current logged in browser session
   * @deprecated Use `viewerSession` instead.
   */
  currentBrowserSession?: Maybe<BrowserSession>;
  /**
   * Get the current logged in user
   * @deprecated Use `viewer` instead.
   */
  currentUser?: Maybe<User>;
  /** Fetches an object given its ID. */
  node?: Maybe<Node>;
  /** Fetch an OAuth 2.0 client by its ID. */
  oauth2Client?: Maybe<Oauth2Client>;
  /** Fetch an upstream OAuth 2.0 link by its ID. */
  upstreamOauth2Link?: Maybe<UpstreamOAuth2Link>;
  /** Fetch an upstream OAuth 2.0 provider by its ID. */
  upstreamOauth2Provider?: Maybe<UpstreamOAuth2Provider>;
  /** Get a list of upstream OAuth 2.0 providers. */
  upstreamOauth2Providers: UpstreamOAuth2ProviderConnection;
  /** Fetch a user by its ID. */
  user?: Maybe<User>;
  /** Fetch a user email by its ID. */
  userEmail?: Maybe<UserEmail>;
  /** Get the viewer */
  viewer: Viewer;
  /** Get the viewer's session */
  viewerSession: ViewerSession;
};


/** The query root of the GraphQL interface. */
export type QueryBrowserSessionArgs = {
  id: Scalars['ID'];
};


/** The query root of the GraphQL interface. */
export type QueryNodeArgs = {
  id: Scalars['ID'];
};


/** The query root of the GraphQL interface. */
export type QueryOauth2ClientArgs = {
  id: Scalars['ID'];
};


/** The query root of the GraphQL interface. */
export type QueryUpstreamOauth2LinkArgs = {
  id: Scalars['ID'];
};


/** The query root of the GraphQL interface. */
export type QueryUpstreamOauth2ProviderArgs = {
  id: Scalars['ID'];
};


/** The query root of the GraphQL interface. */
export type QueryUpstreamOauth2ProvidersArgs = {
  after?: InputMaybe<Scalars['String']>;
  before?: InputMaybe<Scalars['String']>;
  first?: InputMaybe<Scalars['Int']>;
  last?: InputMaybe<Scalars['Int']>;
};


/** The query root of the GraphQL interface. */
export type QueryUserArgs = {
  id: Scalars['ID'];
};


/** The query root of the GraphQL interface. */
export type QueryUserEmailArgs = {
  id: Scalars['ID'];
};

/** The input for the `sendVerificationEmail` mutation */
export type SendVerificationEmailInput = {
  /** The ID of the email address to verify */
  userEmailId: Scalars['ID'];
};

/** The payload of the `sendVerificationEmail` mutation */
export type SendVerificationEmailPayload = {
  __typename?: 'SendVerificationEmailPayload';
  /** The email address to which the verification email was sent */
  email: UserEmail;
  /** Status of the operation */
  status: SendVerificationEmailStatus;
  /** The user to whom the email address belongs */
  user: User;
};

/** The status of the `sendVerificationEmail` mutation */
export enum SendVerificationEmailStatus {
  /** The email address is already verified */
  AlreadyVerified = 'ALREADY_VERIFIED',
  /** The verification email was sent */
  Sent = 'SENT'
}

export type UpstreamOAuth2Link = CreationEvent & Node & {
  __typename?: 'UpstreamOAuth2Link';
  /** When the object was created. */
  createdAt: Scalars['DateTime'];
  /** ID of the object. */
  id: Scalars['ID'];
  /** The provider for which this link is. */
  provider: UpstreamOAuth2Provider;
  /** Subject used for linking */
  subject: Scalars['String'];
  /** The user to which this link is associated. */
  user?: Maybe<User>;
};

export type UpstreamOAuth2LinkConnection = {
  __typename?: 'UpstreamOAuth2LinkConnection';
  /** A list of edges. */
  edges: Array<UpstreamOAuth2LinkEdge>;
  /** A list of nodes. */
  nodes: Array<UpstreamOAuth2Link>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
};

/** An edge in a connection. */
export type UpstreamOAuth2LinkEdge = {
  __typename?: 'UpstreamOAuth2LinkEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String'];
  /** The item at the end of the edge */
  node: UpstreamOAuth2Link;
};

export type UpstreamOAuth2Provider = CreationEvent & Node & {
  __typename?: 'UpstreamOAuth2Provider';
  /** Client ID used for this provider. */
  clientId: Scalars['String'];
  /** When the object was created. */
  createdAt: Scalars['DateTime'];
  /** ID of the object. */
  id: Scalars['ID'];
  /** OpenID Connect issuer URL. */
  issuer: Scalars['String'];
};

export type UpstreamOAuth2ProviderConnection = {
  __typename?: 'UpstreamOAuth2ProviderConnection';
  /** A list of edges. */
  edges: Array<UpstreamOAuth2ProviderEdge>;
  /** A list of nodes. */
  nodes: Array<UpstreamOAuth2Provider>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
};

/** An edge in a connection. */
export type UpstreamOAuth2ProviderEdge = {
  __typename?: 'UpstreamOAuth2ProviderEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String'];
  /** The item at the end of the edge */
  node: UpstreamOAuth2Provider;
};

/** A user is an individual's account. */
export type User = Node & {
  __typename?: 'User';
  /** Get the list of active browser sessions, chronologically sorted */
  browserSessions: BrowserSessionConnection;
  /** Get the list of compatibility SSO logins, chronologically sorted */
  compatSsoLogins: CompatSsoLoginConnection;
  /** Get the list of emails, chronologically sorted */
  emails: UserEmailConnection;
  /** ID of the object. */
  id: Scalars['ID'];
  /** Get the list of OAuth 2.0 sessions, chronologically sorted */
  oauth2Sessions: Oauth2SessionConnection;
  /** Primary email address of the user. */
  primaryEmail?: Maybe<UserEmail>;
  /** Get the list of upstream OAuth 2.0 links */
  upstreamOauth2Links: UpstreamOAuth2LinkConnection;
  /** Username chosen by the user. */
  username: Scalars['String'];
};


/** A user is an individual's account. */
export type UserBrowserSessionsArgs = {
  after?: InputMaybe<Scalars['String']>;
  before?: InputMaybe<Scalars['String']>;
  first?: InputMaybe<Scalars['Int']>;
  last?: InputMaybe<Scalars['Int']>;
};


/** A user is an individual's account. */
export type UserCompatSsoLoginsArgs = {
  after?: InputMaybe<Scalars['String']>;
  before?: InputMaybe<Scalars['String']>;
  first?: InputMaybe<Scalars['Int']>;
  last?: InputMaybe<Scalars['Int']>;
};


/** A user is an individual's account. */
export type UserEmailsArgs = {
  after?: InputMaybe<Scalars['String']>;
  before?: InputMaybe<Scalars['String']>;
  first?: InputMaybe<Scalars['Int']>;
  last?: InputMaybe<Scalars['Int']>;
};


/** A user is an individual's account. */
export type UserOauth2SessionsArgs = {
  after?: InputMaybe<Scalars['String']>;
  before?: InputMaybe<Scalars['String']>;
  first?: InputMaybe<Scalars['Int']>;
  last?: InputMaybe<Scalars['Int']>;
};


/** A user is an individual's account. */
export type UserUpstreamOauth2LinksArgs = {
  after?: InputMaybe<Scalars['String']>;
  before?: InputMaybe<Scalars['String']>;
  first?: InputMaybe<Scalars['Int']>;
  last?: InputMaybe<Scalars['Int']>;
};

/** A user email address */
export type UserEmail = CreationEvent & Node & {
  __typename?: 'UserEmail';
  /**
   * When the email address was confirmed. Is `null` if the email was never
   * verified by the user.
   */
  confirmedAt?: Maybe<Scalars['DateTime']>;
  /** When the object was created. */
  createdAt: Scalars['DateTime'];
  /** Email address */
  email: Scalars['String'];
  /** ID of the object. */
  id: Scalars['ID'];
};

export type UserEmailConnection = {
  __typename?: 'UserEmailConnection';
  /** A list of edges. */
  edges: Array<UserEmailEdge>;
  /** A list of nodes. */
  nodes: Array<UserEmail>;
  /** Information to aid in pagination. */
  pageInfo: PageInfo;
  /** Identifies the total count of items in the connection. */
  totalCount: Scalars['Int'];
};

/** An edge in a connection. */
export type UserEmailEdge = {
  __typename?: 'UserEmailEdge';
  /** A cursor for use in pagination */
  cursor: Scalars['String'];
  /** The item at the end of the edge */
  node: UserEmail;
};

/** The input for the `verifyEmail` mutation */
export type VerifyEmailInput = {
  /** The verification code */
  code: Scalars['String'];
  /** The ID of the email address to verify */
  userEmailId: Scalars['ID'];
};

/** The payload of the `verifyEmail` mutation */
export type VerifyEmailPayload = {
  __typename?: 'VerifyEmailPayload';
  /** The email address that was verified */
  email?: Maybe<UserEmail>;
  /** Status of the operation */
  status: VerifyEmailStatus;
  /** The user to whom the email address belongs */
  user?: Maybe<User>;
};

/** The status of the `verifyEmail` mutation */
export enum VerifyEmailStatus {
  /** The email address was already verified before */
  AlreadyVerified = 'ALREADY_VERIFIED',
  /** The verification code is invalid */
  InvalidCode = 'INVALID_CODE',
  /** The email address was just verified */
  Verified = 'VERIFIED'
}

/** Represents the current viewer */
export type Viewer = Anonymous | User;

/** Represents the current viewer's session */
export type ViewerSession = Anonymous | BrowserSession;

export type BrowserSession_SessionFragment = { __typename?: 'BrowserSession', id: string, createdAt: any, lastAuthentication?: { __typename?: 'Authentication', id: string, createdAt: any } | null } & { ' $fragmentName'?: 'BrowserSession_SessionFragment' };

export type BrowserSessionList_UserFragment = { __typename?: 'User', browserSessions: { __typename?: 'BrowserSessionConnection', edges: Array<{ __typename?: 'BrowserSessionEdge', cursor: string, node: (
        { __typename?: 'BrowserSession', id: string }
        & { ' $fragmentRefs'?: { 'BrowserSession_SessionFragment': BrowserSession_SessionFragment } }
      ) }> } } & { ' $fragmentName'?: 'BrowserSessionList_UserFragment' };

export type CompatSsoLogin_LoginFragment = { __typename?: 'CompatSsoLogin', id: string, redirectUri: any, createdAt: any, session?: { __typename?: 'CompatSession', id: string, createdAt: any, deviceId: string, finishedAt?: any | null } | null } & { ' $fragmentName'?: 'CompatSsoLogin_LoginFragment' };

export type CompatSsoLoginList_UserFragment = { __typename?: 'User', compatSsoLogins: { __typename?: 'CompatSsoLoginConnection', edges: Array<{ __typename?: 'CompatSsoLoginEdge', node: (
        { __typename?: 'CompatSsoLogin', id: string }
        & { ' $fragmentRefs'?: { 'CompatSsoLogin_LoginFragment': CompatSsoLogin_LoginFragment } }
      ) }> } } & { ' $fragmentName'?: 'CompatSsoLoginList_UserFragment' };

export type OAuth2Session_SessionFragment = { __typename?: 'Oauth2Session', id: string, scope: string, client: { __typename?: 'Oauth2Client', id: string, clientId: string, clientName?: string | null, clientUri?: any | null } } & { ' $fragmentName'?: 'OAuth2Session_SessionFragment' };

export type OAuth2SessionList_UserFragment = { __typename?: 'User', oauth2Sessions: { __typename?: 'Oauth2SessionConnection', edges: Array<{ __typename?: 'Oauth2SessionEdge', cursor: string, node: (
        { __typename?: 'Oauth2Session', id: string }
        & { ' $fragmentRefs'?: { 'OAuth2Session_SessionFragment': OAuth2Session_SessionFragment } }
      ) }> } } & { ' $fragmentName'?: 'OAuth2SessionList_UserFragment' };

export type BrowserSessionQueryQueryVariables = Exact<{
  id: Scalars['ID'];
}>;


export type BrowserSessionQueryQuery = { __typename?: 'Query', browserSession?: { __typename?: 'BrowserSession', id: string, createdAt: any, lastAuthentication?: { __typename?: 'Authentication', id: string, createdAt: any } | null, user: { __typename?: 'User', id: string, username: string } } | null };

export type HomeQueryQueryVariables = Exact<{
  count: Scalars['Int'];
  cursor?: InputMaybe<Scalars['String']>;
}>;


export type HomeQueryQuery = { __typename?: 'Query', currentBrowserSession?: { __typename?: 'BrowserSession', id: string, user: (
      { __typename?: 'User', id: string, username: string }
      & { ' $fragmentRefs'?: { 'CompatSsoLoginList_UserFragment': CompatSsoLoginList_UserFragment;'BrowserSessionList_UserFragment': BrowserSessionList_UserFragment;'OAuth2SessionList_UserFragment': OAuth2SessionList_UserFragment } }
    ) } | null };

export type OAuth2ClientQueryQueryVariables = Exact<{
  id: Scalars['ID'];
}>;


export type OAuth2ClientQueryQuery = { __typename?: 'Query', oauth2Client?: { __typename?: 'Oauth2Client', id: string, clientId: string, clientName?: string | null, clientUri?: any | null, tosUri?: any | null, policyUri?: any | null, redirectUris: Array<any> } | null };

export const BrowserSession_SessionFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSession_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}}]}}]} as unknown as DocumentNode<BrowserSession_SessionFragment, unknown>;
export const BrowserSessionList_UserFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSessionList_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"browserSessions"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"count"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"cursor"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"cursor"}},{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"BrowserSession_session"}}]}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSession_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}}]}}]} as unknown as DocumentNode<BrowserSessionList_UserFragment, unknown>;
export const CompatSsoLogin_LoginFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSsoLogin_login"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"CompatSsoLogin"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUri"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"session"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"deviceId"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}}]}}]}}]} as unknown as DocumentNode<CompatSsoLogin_LoginFragment, unknown>;
export const CompatSsoLoginList_UserFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSsoLoginList_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"compatSsoLogins"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"count"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"cursor"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"CompatSsoLogin_login"}}]}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSsoLogin_login"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"CompatSsoLogin"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUri"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"session"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"deviceId"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}}]}}]}}]} as unknown as DocumentNode<CompatSsoLoginList_UserFragment, unknown>;
export const OAuth2Session_SessionFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Session_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Session"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"scope"}},{"kind":"Field","name":{"kind":"Name","value":"client"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"clientUri"}}]}}]}}]} as unknown as DocumentNode<OAuth2Session_SessionFragment, unknown>;
export const OAuth2SessionList_UserFragmentDoc = {"kind":"Document","definitions":[{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2SessionList_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"oauth2Sessions"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"count"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"cursor"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"cursor"}},{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"OAuth2Session_session"}}]}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Session_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Session"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"scope"}},{"kind":"Field","name":{"kind":"Name","value":"client"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"clientUri"}}]}}]}}]} as unknown as DocumentNode<OAuth2SessionList_UserFragment, unknown>;
export const BrowserSessionQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"BrowserSessionQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"browserSession"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"id"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"username"}}]}}]}}]}}]} as unknown as DocumentNode<BrowserSessionQueryQuery, BrowserSessionQueryQueryVariables>;
export const HomeQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"HomeQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"count"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"Int"}}}},{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"cursor"}},"type":{"kind":"NamedType","name":{"kind":"Name","value":"String"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"currentBrowserSession"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"user"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"username"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"CompatSsoLoginList_user"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"BrowserSessionList_user"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"OAuth2SessionList_user"}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSsoLogin_login"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"CompatSsoLogin"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUri"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"session"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"deviceId"}},{"kind":"Field","name":{"kind":"Name","value":"finishedAt"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSession_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"BrowserSession"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}},{"kind":"Field","name":{"kind":"Name","value":"lastAuthentication"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"createdAt"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2Session_session"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"Oauth2Session"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"scope"}},{"kind":"Field","name":{"kind":"Name","value":"client"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"clientUri"}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"CompatSsoLoginList_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"compatSsoLogins"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"count"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"cursor"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"CompatSsoLogin_login"}}]}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"BrowserSessionList_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"browserSessions"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"count"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"cursor"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"cursor"}},{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"BrowserSession_session"}}]}}]}}]}}]}},{"kind":"FragmentDefinition","name":{"kind":"Name","value":"OAuth2SessionList_user"},"typeCondition":{"kind":"NamedType","name":{"kind":"Name","value":"User"}},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"oauth2Sessions"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"first"},"value":{"kind":"Variable","name":{"kind":"Name","value":"count"}}},{"kind":"Argument","name":{"kind":"Name","value":"after"},"value":{"kind":"Variable","name":{"kind":"Name","value":"cursor"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"edges"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"cursor"}},{"kind":"Field","name":{"kind":"Name","value":"node"},"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"FragmentSpread","name":{"kind":"Name","value":"OAuth2Session_session"}}]}}]}}]}}]}}]} as unknown as DocumentNode<HomeQueryQuery, HomeQueryQueryVariables>;
export const OAuth2ClientQueryDocument = {"kind":"Document","definitions":[{"kind":"OperationDefinition","operation":"query","name":{"kind":"Name","value":"OAuth2ClientQuery"},"variableDefinitions":[{"kind":"VariableDefinition","variable":{"kind":"Variable","name":{"kind":"Name","value":"id"}},"type":{"kind":"NonNullType","type":{"kind":"NamedType","name":{"kind":"Name","value":"ID"}}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"oauth2Client"},"arguments":[{"kind":"Argument","name":{"kind":"Name","value":"id"},"value":{"kind":"Variable","name":{"kind":"Name","value":"id"}}}],"selectionSet":{"kind":"SelectionSet","selections":[{"kind":"Field","name":{"kind":"Name","value":"id"}},{"kind":"Field","name":{"kind":"Name","value":"clientId"}},{"kind":"Field","name":{"kind":"Name","value":"clientName"}},{"kind":"Field","name":{"kind":"Name","value":"clientUri"}},{"kind":"Field","name":{"kind":"Name","value":"tosUri"}},{"kind":"Field","name":{"kind":"Name","value":"policyUri"}},{"kind":"Field","name":{"kind":"Name","value":"redirectUris"}}]}}]}}]} as unknown as DocumentNode<OAuth2ClientQueryQuery, OAuth2ClientQueryQueryVariables>;