/**
 * @generated SignedSource<<f53c0d7dd710ddd990f1dc215274fc5f>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { ConcreteRequest, Query } from 'relay-runtime';
export type BrowserSessionQuery$variables = {
  id: string;
};
export type BrowserSessionQuery$data = {
  readonly browserSession: {
    readonly createdAt: any;
    readonly id: string;
    readonly lastAuthentication: {
      readonly createdAt: any;
      readonly id: string;
    } | null;
    readonly user: {
      readonly id: string;
      readonly username: string;
    };
  } | null;
};
export type BrowserSessionQuery = {
  response: BrowserSessionQuery$data;
  variables: BrowserSessionQuery$variables;
};

const node: ConcreteRequest = (function(){
var v0 = [
  {
    "defaultValue": null,
    "kind": "LocalArgument",
    "name": "id"
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
  "name": "createdAt",
  "storageKey": null
},
v3 = [
  {
    "alias": null,
    "args": [
      {
        "kind": "Variable",
        "name": "id",
        "variableName": "id"
      }
    ],
    "concreteType": "BrowserSession",
    "kind": "LinkedField",
    "name": "browserSession",
    "plural": false,
    "selections": [
      (v1/*: any*/),
      (v2/*: any*/),
      {
        "alias": null,
        "args": null,
        "concreteType": "Authentication",
        "kind": "LinkedField",
        "name": "lastAuthentication",
        "plural": false,
        "selections": [
          (v1/*: any*/),
          (v2/*: any*/)
        ],
        "storageKey": null
      },
      {
        "alias": null,
        "args": null,
        "concreteType": "User",
        "kind": "LinkedField",
        "name": "user",
        "plural": false,
        "selections": [
          (v1/*: any*/),
          {
            "alias": null,
            "args": null,
            "kind": "ScalarField",
            "name": "username",
            "storageKey": null
          }
        ],
        "storageKey": null
      }
    ],
    "storageKey": null
  }
];
return {
  "fragment": {
    "argumentDefinitions": (v0/*: any*/),
    "kind": "Fragment",
    "metadata": null,
    "name": "BrowserSessionQuery",
    "selections": (v3/*: any*/),
    "type": "RootQuery",
    "abstractKey": null
  },
  "kind": "Request",
  "operation": {
    "argumentDefinitions": (v0/*: any*/),
    "kind": "Operation",
    "name": "BrowserSessionQuery",
    "selections": (v3/*: any*/)
  },
  "params": {
    "cacheID": "5374afccfa4da28a64cdce6585ac1907",
    "id": null,
    "metadata": {},
    "name": "BrowserSessionQuery",
    "operationKind": "query",
    "text": "query BrowserSessionQuery(\n  $id: ID!\n) {\n  browserSession(id: $id) {\n    id\n    createdAt\n    lastAuthentication {\n      id\n      createdAt\n    }\n    user {\n      id\n      username\n    }\n  }\n}\n"
  }
};
})();

(node as any).hash = "c73293a99a0214448861bed340594304";

export default node;
