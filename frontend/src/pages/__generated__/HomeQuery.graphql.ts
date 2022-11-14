/**
 * @generated SignedSource<<94462aca9c48eae79c22a11003d865c3>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { ConcreteRequest, Query } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type HomeQuery$variables = {};
export type HomeQuery$data = {
  readonly currentUser: {
    readonly id: string;
    readonly username: string;
    readonly " $fragmentSpreads": FragmentRefs<"CompatSsoLoginList_user">;
  } | null;
};
export type HomeQuery = {
  response: HomeQuery$data;
  variables: HomeQuery$variables;
};

const node: ConcreteRequest = (function(){
var v0 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "id",
  "storageKey": null
},
v1 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "username",
  "storageKey": null
};
return {
  "fragment": {
    "argumentDefinitions": [],
    "kind": "Fragment",
    "metadata": null,
    "name": "HomeQuery",
    "selections": [
      {
        "alias": null,
        "args": null,
        "concreteType": "User",
        "kind": "LinkedField",
        "name": "currentUser",
        "plural": false,
        "selections": [
          (v0/*: any*/),
          (v1/*: any*/),
          {
            "args": null,
            "kind": "FragmentSpread",
            "name": "CompatSsoLoginList_user"
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
    "argumentDefinitions": [],
    "kind": "Operation",
    "name": "HomeQuery",
    "selections": [
      {
        "alias": null,
        "args": null,
        "concreteType": "User",
        "kind": "LinkedField",
        "name": "currentUser",
        "plural": false,
        "selections": [
          (v0/*: any*/),
          (v1/*: any*/),
          {
            "alias": null,
            "args": [
              {
                "kind": "Literal",
                "name": "first",
                "value": 10
              }
            ],
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
                      (v0/*: any*/),
                      {
                        "alias": null,
                        "args": null,
                        "kind": "ScalarField",
                        "name": "redirectUri",
                        "storageKey": null
                      }
                    ],
                    "storageKey": null
                  }
                ],
                "storageKey": null
              }
            ],
            "storageKey": "compatSsoLogins(first:10)"
          }
        ],
        "storageKey": null
      }
    ]
  },
  "params": {
    "cacheID": "1b4d3469bb6ccc19b8944b1f7fedd9c5",
    "id": null,
    "metadata": {},
    "name": "HomeQuery",
    "operationKind": "query",
    "text": "query HomeQuery {\n  currentUser {\n    id\n    username\n    ...CompatSsoLoginList_user\n  }\n}\n\nfragment CompatSsoLoginList_user on User {\n  compatSsoLogins(first: 10) {\n    edges {\n      node {\n        ...CompatSsoLogin_login\n        id\n      }\n    }\n  }\n}\n\nfragment CompatSsoLogin_login on CompatSsoLogin {\n  id\n  redirectUri\n}\n"
  }
};
})();

(node as any).hash = "a5defd2dc81b62abebfe7a393573d5a8";

export default node;
