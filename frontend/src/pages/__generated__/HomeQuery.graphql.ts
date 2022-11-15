/**
 * @generated SignedSource<<b9d5536e28bde5c8929747fab28aae0e>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { ConcreteRequest, Query } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type HomeQuery$variables = {
  count: number;
  cursor?: string | null;
};
export type HomeQuery$data = {
  readonly currentBrowserSession: {
    readonly id: string;
    readonly user: {
      readonly id: string;
      readonly username: string;
      readonly " $fragmentSpreads": FragmentRefs<"BrowserSessionList_user" | "CompatSsoLoginList_user" | "OAuth2SessionList_user">;
    };
  } | null;
};
export type HomeQuery = {
  response: HomeQuery$data;
  variables: HomeQuery$variables;
};

const node: ConcreteRequest = (function(){
var v0 = [
  {
    "defaultValue": null,
    "kind": "LocalArgument",
    "name": "count"
  },
  {
    "defaultValue": null,
    "kind": "LocalArgument",
    "name": "cursor"
  }
],
v1 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "id",
  "storageKey": null
},
v2 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "username",
  "storageKey": null
},
v3 = [
  {
    "kind": "Variable",
    "name": "after",
    "variableName": "cursor"
  },
  {
    "kind": "Variable",
    "name": "first",
    "variableName": "count"
  }
],
v4 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "createdAt",
  "storageKey": null
},
v5 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "__typename",
  "storageKey": null
},
v6 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "cursor",
  "storageKey": null
},
v7 = {
  "alias": null,
  "args": null,
  "concreteType": "PageInfo",
  "kind": "LinkedField",
  "name": "pageInfo",
  "plural": false,
  "selections": [
    {
      "alias": null,
      "args": null,
      "kind": "ScalarField",
      "name": "endCursor",
      "storageKey": null
    },
    {
      "alias": null,
      "args": null,
      "kind": "ScalarField",
      "name": "hasNextPage",
      "storageKey": null
    }
  ],
  "storageKey": null
};
return {
  "fragment": {
    "argumentDefinitions": (v0/*: any*/),
    "kind": "Fragment",
    "metadata": null,
    "name": "HomeQuery",
    "selections": [
      {
        "alias": null,
        "args": null,
        "concreteType": "BrowserSession",
        "kind": "LinkedField",
        "name": "currentBrowserSession",
        "plural": false,
        "selections": [
          (v1/*: any*/),
          {
            "alias": null,
            "args": null,
            "concreteType": "User",
            "kind": "LinkedField",
            "name": "user",
            "plural": false,
            "selections": [
              (v1/*: any*/),
              (v2/*: any*/),
              {
                "args": null,
                "kind": "FragmentSpread",
                "name": "CompatSsoLoginList_user"
              },
              {
                "args": null,
                "kind": "FragmentSpread",
                "name": "BrowserSessionList_user"
              },
              {
                "args": null,
                "kind": "FragmentSpread",
                "name": "OAuth2SessionList_user"
              }
            ],
            "storageKey": null
          }
        ],
        "storageKey": null
      }
    ],
    "type": "RootQuery",
    "abstractKey": null
  },
  "kind": "Request",
  "operation": {
    "argumentDefinitions": (v0/*: any*/),
    "kind": "Operation",
    "name": "HomeQuery",
    "selections": [
      {
        "alias": null,
        "args": null,
        "concreteType": "BrowserSession",
        "kind": "LinkedField",
        "name": "currentBrowserSession",
        "plural": false,
        "selections": [
          (v1/*: any*/),
          {
            "alias": null,
            "args": null,
            "concreteType": "User",
            "kind": "LinkedField",
            "name": "user",
            "plural": false,
            "selections": [
              (v1/*: any*/),
              (v2/*: any*/),
              {
                "alias": null,
                "args": (v3/*: any*/),
                "concreteType": "CompatSsoLoginConnection",
                "kind": "LinkedField",
                "name": "compatSsoLogins",
                "plural": false,
                "selections": [
                  {
                    "alias": null,
                    "args": null,
                    "concreteType": "CompatSsoLoginEdge",
                    "kind": "LinkedField",
                    "name": "edges",
                    "plural": true,
                    "selections": [
                      {
                        "alias": null,
                        "args": null,
                        "concreteType": "CompatSsoLogin",
                        "kind": "LinkedField",
                        "name": "node",
                        "plural": false,
                        "selections": [
                          (v1/*: any*/),
                          {
                            "alias": null,
                            "args": null,
                            "kind": "ScalarField",
                            "name": "redirectUri",
                            "storageKey": null
                          },
                          (v4/*: any*/),
                          {
                            "alias": null,
                            "args": null,
                            "concreteType": "CompatSession",
                            "kind": "LinkedField",
                            "name": "session",
                            "plural": false,
                            "selections": [
                              (v1/*: any*/),
                              (v4/*: any*/),
                              {
                                "alias": null,
                                "args": null,
                                "kind": "ScalarField",
                                "name": "deviceId",
                                "storageKey": null
                              },
                              {
                                "alias": null,
                                "args": null,
                                "kind": "ScalarField",
                                "name": "finishedAt",
                                "storageKey": null
                              }
                            ],
                            "storageKey": null
                          },
                          (v5/*: any*/)
                        ],
                        "storageKey": null
                      },
                      (v6/*: any*/)
                    ],
                    "storageKey": null
                  },
                  (v7/*: any*/)
                ],
                "storageKey": null
              },
              {
                "alias": null,
                "args": (v3/*: any*/),
                "filters": null,
                "handle": "connection",
                "key": "CompatSsoLoginList_user_compatSsoLogins",
                "kind": "LinkedHandle",
                "name": "compatSsoLogins"
              },
              {
                "alias": null,
                "args": (v3/*: any*/),
                "concreteType": "BrowserSessionConnection",
                "kind": "LinkedField",
                "name": "browserSessions",
                "plural": false,
                "selections": [
                  {
                    "alias": null,
                    "args": null,
                    "concreteType": "BrowserSessionEdge",
                    "kind": "LinkedField",
                    "name": "edges",
                    "plural": true,
                    "selections": [
                      (v6/*: any*/),
                      {
                        "alias": null,
                        "args": null,
                        "concreteType": "BrowserSession",
                        "kind": "LinkedField",
                        "name": "node",
                        "plural": false,
                        "selections": [
                          (v1/*: any*/),
                          (v4/*: any*/),
                          {
                            "alias": null,
                            "args": null,
                            "concreteType": "Authentication",
                            "kind": "LinkedField",
                            "name": "lastAuthentication",
                            "plural": false,
                            "selections": [
                              (v1/*: any*/),
                              (v4/*: any*/)
                            ],
                            "storageKey": null
                          },
                          (v5/*: any*/)
                        ],
                        "storageKey": null
                      }
                    ],
                    "storageKey": null
                  },
                  (v7/*: any*/)
                ],
                "storageKey": null
              },
              {
                "alias": null,
                "args": (v3/*: any*/),
                "filters": null,
                "handle": "connection",
                "key": "BrowserSessionList_user_browserSessions",
                "kind": "LinkedHandle",
                "name": "browserSessions"
              },
              {
                "alias": null,
                "args": (v3/*: any*/),
                "concreteType": "Oauth2SessionConnection",
                "kind": "LinkedField",
                "name": "oauth2Sessions",
                "plural": false,
                "selections": [
                  {
                    "alias": null,
                    "args": null,
                    "concreteType": "Oauth2SessionEdge",
                    "kind": "LinkedField",
                    "name": "edges",
                    "plural": true,
                    "selections": [
                      (v6/*: any*/),
                      {
                        "alias": null,
                        "args": null,
                        "concreteType": "Oauth2Session",
                        "kind": "LinkedField",
                        "name": "node",
                        "plural": false,
                        "selections": [
                          (v1/*: any*/),
                          {
                            "alias": null,
                            "args": null,
                            "kind": "ScalarField",
                            "name": "scope",
                            "storageKey": null
                          },
                          {
                            "alias": null,
                            "args": null,
                            "concreteType": "Oauth2Client",
                            "kind": "LinkedField",
                            "name": "client",
                            "plural": false,
                            "selections": [
                              (v1/*: any*/),
                              {
                                "alias": null,
                                "args": null,
                                "kind": "ScalarField",
                                "name": "clientId",
                                "storageKey": null
                              },
                              {
                                "alias": null,
                                "args": null,
                                "kind": "ScalarField",
                                "name": "clientName",
                                "storageKey": null
                              },
                              {
                                "alias": null,
                                "args": null,
                                "kind": "ScalarField",
                                "name": "clientUri",
                                "storageKey": null
                              }
                            ],
                            "storageKey": null
                          },
                          (v5/*: any*/)
                        ],
                        "storageKey": null
                      }
                    ],
                    "storageKey": null
                  },
                  (v7/*: any*/)
                ],
                "storageKey": null
              },
              {
                "alias": null,
                "args": (v3/*: any*/),
                "filters": null,
                "handle": "connection",
                "key": "OAuth2SessionList_user_oauth2Sessions",
                "kind": "LinkedHandle",
                "name": "oauth2Sessions"
              }
            ],
            "storageKey": null
          }
        ],
        "storageKey": null
      }
    ]
  },
  "params": {
    "cacheID": "c2c8afebb1acbce26f8d164d911c5833",
    "id": null,
    "metadata": {},
    "name": "HomeQuery",
    "operationKind": "query",
    "text": "query HomeQuery(\n  $count: Int!\n  $cursor: String\n) {\n  currentBrowserSession {\n    id\n    user {\n      id\n      username\n      ...CompatSsoLoginList_user\n      ...BrowserSessionList_user\n      ...OAuth2SessionList_user\n    }\n  }\n}\n\nfragment BrowserSessionList_user on User {\n  browserSessions(first: $count, after: $cursor) {\n    edges {\n      cursor\n      node {\n        id\n        ...BrowserSession_session\n        __typename\n      }\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n    }\n  }\n  id\n}\n\nfragment BrowserSession_session on BrowserSession {\n  id\n  createdAt\n  lastAuthentication {\n    id\n    createdAt\n  }\n}\n\nfragment CompatSsoLoginList_user on User {\n  compatSsoLogins(first: $count, after: $cursor) {\n    edges {\n      node {\n        id\n        ...CompatSsoLogin_login\n        __typename\n      }\n      cursor\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n    }\n  }\n  id\n}\n\nfragment CompatSsoLogin_login on CompatSsoLogin {\n  id\n  redirectUri\n  createdAt\n  session {\n    id\n    createdAt\n    deviceId\n    finishedAt\n  }\n}\n\nfragment OAuth2SessionList_user on User {\n  oauth2Sessions(first: $count, after: $cursor) {\n    edges {\n      cursor\n      node {\n        id\n        ...OAuth2Session_session\n        __typename\n      }\n    }\n    pageInfo {\n      endCursor\n      hasNextPage\n    }\n  }\n  id\n}\n\nfragment OAuth2Session_session on Oauth2Session {\n  id\n  scope\n  client {\n    id\n    clientId\n    clientName\n    clientUri\n  }\n}\n"
  }
};
})();

(node as any).hash = "f26e9c3756edccc8584de5f359fd96bd";

export default node;
