/**
 * @generated SignedSource<<20e2b233e5154ea60632046abc2aa29a>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { Fragment, ReaderFragment } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type CompatSsoLogin_login$data = {
  readonly createdAt: any;
  readonly id: string;
  readonly redirectUri: any;
  readonly session: {
    readonly createdAt: any;
    readonly deviceId: string;
    readonly finishedAt: any | null;
    readonly id: string;
  } | null;
  readonly " $fragmentType": "CompatSsoLogin_login";
};
export type CompatSsoLogin_login$key = {
  readonly " $data"?: CompatSsoLogin_login$data;
  readonly " $fragmentSpreads": FragmentRefs<"CompatSsoLogin_login">;
};

const node: ReaderFragment = (function(){
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
  "name": "createdAt",
  "storageKey": null
};
return {
  "argumentDefinitions": [],
  "kind": "Fragment",
  "metadata": null,
  "name": "CompatSsoLogin_login",
  "selections": [
    (v0/*: any*/),
    {
      "alias": null,
      "args": null,
      "kind": "ScalarField",
      "name": "redirectUri",
      "storageKey": null
    },
    (v1/*: any*/),
    {
      "alias": null,
      "args": null,
      "concreteType": "CompatSession",
      "kind": "LinkedField",
      "name": "session",
      "plural": false,
      "selections": [
        (v0/*: any*/),
        (v1/*: any*/),
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
    }
  ],
  "type": "CompatSsoLogin",
  "abstractKey": null
};
})();

(node as any).hash = "7be3b416b1023cea0de7a87b9738e5d5";

export default node;
