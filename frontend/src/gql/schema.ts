/* eslint-disable */
import { IntrospectionQuery } from "graphql";
export default {
  __schema: {
    queryType: {
      name: "Query",
    },
    mutationType: {
      name: "Mutation",
    },
    subscriptionType: null,
    types: [
      {
        kind: "OBJECT",
        name: "AddEmailPayload",
        fields: [
          {
            name: "email",
            type: {
              kind: "OBJECT",
              name: "UserEmail",
              ofType: null,
            },
            args: [],
          },
          {
            name: "status",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "OBJECT",
              name: "User",
              ofType: null,
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "Anonymous",
        fields: [
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "Authentication",
        fields: [
          {
            name: "createdAt",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "CreationEvent",
          },
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "BrowserSession",
        fields: [
          {
            name: "createdAt",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "lastAuthentication",
            type: {
              kind: "OBJECT",
              name: "Authentication",
              ofType: null,
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "User",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "CreationEvent",
          },
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "BrowserSessionConnection",
        fields: [
          {
            name: "edges",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "BrowserSessionEdge",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "nodes",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "BrowserSession",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "pageInfo",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "PageInfo",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "BrowserSessionEdge",
        fields: [
          {
            name: "cursor",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "node",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "BrowserSession",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "CompatSession",
        fields: [
          {
            name: "createdAt",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "deviceId",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "finishedAt",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "User",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "CreationEvent",
          },
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "CompatSsoLogin",
        fields: [
          {
            name: "createdAt",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "exchangedAt",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
          {
            name: "fulfilledAt",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "redirectUri",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "session",
            type: {
              kind: "OBJECT",
              name: "CompatSession",
              ofType: null,
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "CompatSsoLoginConnection",
        fields: [
          {
            name: "edges",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "CompatSsoLoginEdge",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "nodes",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "CompatSsoLogin",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "pageInfo",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "PageInfo",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "CompatSsoLoginEdge",
        fields: [
          {
            name: "cursor",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "node",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "CompatSsoLogin",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "INTERFACE",
        name: "CreationEvent",
        fields: [
          {
            name: "createdAt",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
        ],
        interfaces: [],
        possibleTypes: [
          {
            kind: "OBJECT",
            name: "Authentication",
          },
          {
            kind: "OBJECT",
            name: "BrowserSession",
          },
          {
            kind: "OBJECT",
            name: "CompatSession",
          },
          {
            kind: "OBJECT",
            name: "UpstreamOAuth2Link",
          },
          {
            kind: "OBJECT",
            name: "UpstreamOAuth2Provider",
          },
          {
            kind: "OBJECT",
            name: "UserEmail",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "Mutation",
        fields: [
          {
            name: "addEmail",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "AddEmailPayload",
                ofType: null,
              },
            },
            args: [
              {
                name: "input",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "removeEmail",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "RemoveEmailPayload",
                ofType: null,
              },
            },
            args: [
              {
                name: "input",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "sendVerificationEmail",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "SendVerificationEmailPayload",
                ofType: null,
              },
            },
            args: [
              {
                name: "input",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "setPrimaryEmail",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "SetPrimaryEmailPayload",
                ofType: null,
              },
            },
            args: [
              {
                name: "input",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "verifyEmail",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "VerifyEmailPayload",
                ofType: null,
              },
            },
            args: [
              {
                name: "input",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
        ],
        interfaces: [],
      },
      {
        kind: "INTERFACE",
        name: "Node",
        fields: [
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
        ],
        interfaces: [],
        possibleTypes: [
          {
            kind: "OBJECT",
            name: "Anonymous",
          },
          {
            kind: "OBJECT",
            name: "Authentication",
          },
          {
            kind: "OBJECT",
            name: "BrowserSession",
          },
          {
            kind: "OBJECT",
            name: "CompatSession",
          },
          {
            kind: "OBJECT",
            name: "CompatSsoLogin",
          },
          {
            kind: "OBJECT",
            name: "Oauth2Client",
          },
          {
            kind: "OBJECT",
            name: "Oauth2Session",
          },
          {
            kind: "OBJECT",
            name: "UpstreamOAuth2Link",
          },
          {
            kind: "OBJECT",
            name: "UpstreamOAuth2Provider",
          },
          {
            kind: "OBJECT",
            name: "User",
          },
          {
            kind: "OBJECT",
            name: "UserEmail",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "Oauth2Client",
        fields: [
          {
            name: "clientId",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "clientName",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
          {
            name: "clientUri",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "policyUri",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
          {
            name: "redirectUris",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "tosUri",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "Oauth2Session",
        fields: [
          {
            name: "browserSession",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "BrowserSession",
                ofType: null,
              },
            },
            args: [],
          },
          {
            name: "client",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "Oauth2Client",
                ofType: null,
              },
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "scope",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "User",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "Oauth2SessionConnection",
        fields: [
          {
            name: "edges",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "Oauth2SessionEdge",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "nodes",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "Oauth2Session",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "pageInfo",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "PageInfo",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "Oauth2SessionEdge",
        fields: [
          {
            name: "cursor",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "node",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "Oauth2Session",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "PageInfo",
        fields: [
          {
            name: "endCursor",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
          {
            name: "hasNextPage",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "hasPreviousPage",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "startCursor",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "Query",
        fields: [
          {
            name: "browserSession",
            type: {
              kind: "OBJECT",
              name: "BrowserSession",
              ofType: null,
            },
            args: [
              {
                name: "id",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "currentBrowserSession",
            type: {
              kind: "OBJECT",
              name: "BrowserSession",
              ofType: null,
            },
            args: [],
          },
          {
            name: "currentUser",
            type: {
              kind: "OBJECT",
              name: "User",
              ofType: null,
            },
            args: [],
          },
          {
            name: "node",
            type: {
              kind: "INTERFACE",
              name: "Node",
              ofType: null,
            },
            args: [
              {
                name: "id",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "oauth2Client",
            type: {
              kind: "OBJECT",
              name: "Oauth2Client",
              ofType: null,
            },
            args: [
              {
                name: "id",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "upstreamOauth2Link",
            type: {
              kind: "OBJECT",
              name: "UpstreamOAuth2Link",
              ofType: null,
            },
            args: [
              {
                name: "id",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "upstreamOauth2Provider",
            type: {
              kind: "OBJECT",
              name: "UpstreamOAuth2Provider",
              ofType: null,
            },
            args: [
              {
                name: "id",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "upstreamOauth2Providers",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "UpstreamOAuth2ProviderConnection",
                ofType: null,
              },
            },
            args: [
              {
                name: "after",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "before",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "first",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "last",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
            ],
          },
          {
            name: "user",
            type: {
              kind: "OBJECT",
              name: "User",
              ofType: null,
            },
            args: [
              {
                name: "id",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "userEmail",
            type: {
              kind: "OBJECT",
              name: "UserEmail",
              ofType: null,
            },
            args: [
              {
                name: "id",
                type: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "SCALAR",
                    name: "Any",
                  },
                },
              },
            ],
          },
          {
            name: "viewer",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "UNION",
                name: "Viewer",
                ofType: null,
              },
            },
            args: [],
          },
          {
            name: "viewerSession",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "UNION",
                name: "ViewerSession",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "RemoveEmailPayload",
        fields: [
          {
            name: "email",
            type: {
              kind: "OBJECT",
              name: "UserEmail",
              ofType: null,
            },
            args: [],
          },
          {
            name: "status",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "OBJECT",
              name: "User",
              ofType: null,
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "SendVerificationEmailPayload",
        fields: [
          {
            name: "email",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "UserEmail",
                ofType: null,
              },
            },
            args: [],
          },
          {
            name: "status",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "User",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "SetPrimaryEmailPayload",
        fields: [
          {
            name: "status",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "OBJECT",
              name: "User",
              ofType: null,
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "UpstreamOAuth2Link",
        fields: [
          {
            name: "createdAt",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "provider",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "UpstreamOAuth2Provider",
                ofType: null,
              },
            },
            args: [],
          },
          {
            name: "subject",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "OBJECT",
              name: "User",
              ofType: null,
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "CreationEvent",
          },
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "UpstreamOAuth2LinkConnection",
        fields: [
          {
            name: "edges",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "UpstreamOAuth2LinkEdge",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "nodes",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "UpstreamOAuth2Link",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "pageInfo",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "PageInfo",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "UpstreamOAuth2LinkEdge",
        fields: [
          {
            name: "cursor",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "node",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "UpstreamOAuth2Link",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "UpstreamOAuth2Provider",
        fields: [
          {
            name: "clientId",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "createdAt",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "issuer",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "CreationEvent",
          },
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "UpstreamOAuth2ProviderConnection",
        fields: [
          {
            name: "edges",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "UpstreamOAuth2ProviderEdge",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "nodes",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "UpstreamOAuth2Provider",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "pageInfo",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "PageInfo",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "UpstreamOAuth2ProviderEdge",
        fields: [
          {
            name: "cursor",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "node",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "UpstreamOAuth2Provider",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "User",
        fields: [
          {
            name: "browserSessions",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "BrowserSessionConnection",
                ofType: null,
              },
            },
            args: [
              {
                name: "after",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "before",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "first",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "last",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
            ],
          },
          {
            name: "compatSsoLogins",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "CompatSsoLoginConnection",
                ofType: null,
              },
            },
            args: [
              {
                name: "after",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "before",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "first",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "last",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
            ],
          },
          {
            name: "emails",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "UserEmailConnection",
                ofType: null,
              },
            },
            args: [
              {
                name: "after",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "before",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "first",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "last",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
            ],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "oauth2Sessions",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "Oauth2SessionConnection",
                ofType: null,
              },
            },
            args: [
              {
                name: "after",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "before",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "first",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "last",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
            ],
          },
          {
            name: "primaryEmail",
            type: {
              kind: "OBJECT",
              name: "UserEmail",
              ofType: null,
            },
            args: [],
          },
          {
            name: "upstreamOauth2Links",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "UpstreamOAuth2LinkConnection",
                ofType: null,
              },
            },
            args: [
              {
                name: "after",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "before",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "first",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
              {
                name: "last",
                type: {
                  kind: "SCALAR",
                  name: "Any",
                },
              },
            ],
          },
          {
            name: "username",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "UserEmail",
        fields: [
          {
            name: "confirmedAt",
            type: {
              kind: "SCALAR",
              name: "Any",
            },
            args: [],
          },
          {
            name: "createdAt",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "email",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "id",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
        ],
        interfaces: [
          {
            kind: "INTERFACE",
            name: "CreationEvent",
          },
          {
            kind: "INTERFACE",
            name: "Node",
          },
        ],
      },
      {
        kind: "OBJECT",
        name: "UserEmailConnection",
        fields: [
          {
            name: "edges",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "UserEmailEdge",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "nodes",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "LIST",
                ofType: {
                  kind: "NON_NULL",
                  ofType: {
                    kind: "OBJECT",
                    name: "UserEmail",
                    ofType: null,
                  },
                },
              },
            },
            args: [],
          },
          {
            name: "pageInfo",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "PageInfo",
                ofType: null,
              },
            },
            args: [],
          },
          {
            name: "totalCount",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "UserEmailEdge",
        fields: [
          {
            name: "cursor",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "node",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "OBJECT",
                name: "UserEmail",
                ofType: null,
              },
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "OBJECT",
        name: "VerifyEmailPayload",
        fields: [
          {
            name: "email",
            type: {
              kind: "OBJECT",
              name: "UserEmail",
              ofType: null,
            },
            args: [],
          },
          {
            name: "status",
            type: {
              kind: "NON_NULL",
              ofType: {
                kind: "SCALAR",
                name: "Any",
              },
            },
            args: [],
          },
          {
            name: "user",
            type: {
              kind: "OBJECT",
              name: "User",
              ofType: null,
            },
            args: [],
          },
        ],
        interfaces: [],
      },
      {
        kind: "UNION",
        name: "Viewer",
        possibleTypes: [
          {
            kind: "OBJECT",
            name: "Anonymous",
          },
          {
            kind: "OBJECT",
            name: "User",
          },
        ],
      },
      {
        kind: "UNION",
        name: "ViewerSession",
        possibleTypes: [
          {
            kind: "OBJECT",
            name: "Anonymous",
          },
          {
            kind: "OBJECT",
            name: "BrowserSession",
          },
        ],
      },
      {
        kind: "SCALAR",
        name: "Any",
      },
    ],
    directives: [],
  },
} as unknown as IntrospectionQuery;
