/**
 * @generated SignedSource<<82179715f61e6a03437d696941ceaf16>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { ConcreteRequest, Query } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type OAuth2SessionStoriesQuery$variables = {};
export type OAuth2SessionStoriesQuery$data = {
  readonly session: {
    readonly " $fragmentSpreads": FragmentRefs<"OAuth2Session_session">;
  } | null;
};
export type OAuth2SessionStoriesQuery = {
  response: OAuth2SessionStoriesQuery$data;
  variables: OAuth2SessionStoriesQuery$variables;
};

const node: ConcreteRequest = (function(){
var v0 = [
  {
    "kind": "Literal",
    "name": "id",
    "value": "test-id"
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
  "enumValues": null,
  "nullable": false,
  "plural": false,
  "type": "String"
},
v3 = {
  "enumValues": null,
  "nullable": false,
  "plural": false,
  "type": "ID"
};
return {
  "fragment": {
    "argumentDefinitions": [],
    "kind": "Fragment",
    "metadata": null,
    "name": "OAuth2SessionStoriesQuery",
    "selections": [
      {
        "alias": "session",
        "args": (v0/*: any*/),
        "concreteType": null,
        "kind": "LinkedField",
        "name": "node",
        "plural": false,
        "selections": [
          {
            "args": null,
            "kind": "FragmentSpread",
            "name": "OAuth2Session_session"
          }
        ],
        "storageKey": "node(id:\"test-id\")"
      }
    ],
    "type": "RootQuery",
    "abstractKey": null
  },
  "kind": "Request",
  "operation": {
    "argumentDefinitions": [],
    "kind": "Operation",
    "name": "OAuth2SessionStoriesQuery",
    "selections": [
      {
        "alias": "session",
        "args": (v0/*: any*/),
        "concreteType": null,
        "kind": "LinkedField",
        "name": "node",
        "plural": false,
        "selections": [
          {
            "alias": null,
            "args": null,
            "kind": "ScalarField",
            "name": "__typename",
            "storageKey": null
          },
          (v1/*: any*/),
          {
            "kind": "InlineFragment",
            "selections": [
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
              }
            ],
            "type": "Oauth2Session",
            "abstractKey": null
          }
        ],
        "storageKey": "node(id:\"test-id\")"
      }
    ]
  },
  "params": {
    "cacheID": "2b2911cfb421c557245313732f0813e0",
    "id": null,
    "metadata": {
      "relayTestingSelectionTypeInfo": {
        "session": {
          "enumValues": null,
          "nullable": true,
          "plural": false,
          "type": "Node"
        },
        "session.__typename": (v2/*: any*/),
        "session.client": {
          "enumValues": null,
          "nullable": false,
          "plural": false,
          "type": "Oauth2Client"
        },
        "session.client.clientId": (v2/*: any*/),
        "session.client.clientName": {
          "enumValues": null,
          "nullable": true,
          "plural": false,
          "type": "String"
        },
        "session.client.clientUri": {
          "enumValues": null,
          "nullable": true,
          "plural": false,
          "type": "Url"
        },
        "session.client.id": (v3/*: any*/),
        "session.id": (v3/*: any*/),
        "session.scope": (v2/*: any*/)
      }
    },
    "name": "OAuth2SessionStoriesQuery",
    "operationKind": "query",
    "text": "query OAuth2SessionStoriesQuery {\n  session: node(id: \"test-id\") {\n    __typename\n    ...OAuth2Session_session\n    id\n  }\n}\n\nfragment OAuth2Session_session on Oauth2Session {\n  id\n  scope\n  client {\n    id\n    clientId\n    clientName\n    clientUri\n  }\n}\n"
  }
};
})();

(node as any).hash = "d60f8f0abfc0b70236d89328bc5c0e85";

export default node;
