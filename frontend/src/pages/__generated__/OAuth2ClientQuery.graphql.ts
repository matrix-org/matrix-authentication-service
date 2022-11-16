/**
 * @generated SignedSource<<fdd196c5ae97e597805f98077fefcd7d>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { ConcreteRequest, Query } from 'relay-runtime';
export type OAuth2ClientQuery$variables = {
  id: string;
};
export type OAuth2ClientQuery$data = {
  readonly oauth2Client: {
    readonly clientId: string;
    readonly clientName: string | null;
    readonly clientUri: any | null;
    readonly id: string;
    readonly policyUri: any | null;
    readonly redirectUris: ReadonlyArray<any>;
    readonly tosUri: any | null;
  } | null;
};
export type OAuth2ClientQuery = {
  response: OAuth2ClientQuery$data;
  variables: OAuth2ClientQuery$variables;
};

const node: ConcreteRequest = (function(){
var v0 = [
  {
    "defaultValue": null,
    "kind": "LocalArgument",
    "name": "id"
  }
],
v1 = [
  {
    "alias": null,
    "args": [
      {
        "kind": "Variable",
        "name": "id",
        "variableName": "id"
      }
    ],
    "concreteType": "Oauth2Client",
    "kind": "LinkedField",
    "name": "oauth2Client",
    "plural": false,
    "selections": [
      {
        "alias": null,
        "args": null,
        "kind": "ScalarField",
        "name": "id",
        "storageKey": null
      },
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
      },
      {
        "alias": null,
        "args": null,
        "kind": "ScalarField",
        "name": "tosUri",
        "storageKey": null
      },
      {
        "alias": null,
        "args": null,
        "kind": "ScalarField",
        "name": "policyUri",
        "storageKey": null
      },
      {
        "alias": null,
        "args": null,
        "kind": "ScalarField",
        "name": "redirectUris",
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
    "name": "OAuth2ClientQuery",
    "selections": (v1/*: any*/),
    "type": "RootQuery",
    "abstractKey": null
  },
  "kind": "Request",
  "operation": {
    "argumentDefinitions": (v0/*: any*/),
    "kind": "Operation",
    "name": "OAuth2ClientQuery",
    "selections": (v1/*: any*/)
  },
  "params": {
    "cacheID": "49e24d5c368a8c2c148643b971fe179c",
    "id": null,
    "metadata": {},
    "name": "OAuth2ClientQuery",
    "operationKind": "query",
    "text": "query OAuth2ClientQuery(\n  $id: ID!\n) {\n  oauth2Client(id: $id) {\n    id\n    clientId\n    clientName\n    clientUri\n    tosUri\n    policyUri\n    redirectUris\n  }\n}\n"
  }
};
})();

(node as any).hash = "31b4804eb435b5822480ff57775d13a4";

export default node;
