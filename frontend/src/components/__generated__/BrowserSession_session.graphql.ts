/**
 * @generated SignedSource<<f204c3033b21cfa962537b2dd72f4469>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { Fragment, ReaderFragment } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type BrowserSession_session$data = {
  readonly createdAt: any;
  readonly id: string;
  readonly lastAuthentication: {
    readonly createdAt: any;
    readonly id: string;
  } | null;
  readonly " $fragmentType": "BrowserSession_session";
};
export type BrowserSession_session$key = {
  readonly " $data"?: BrowserSession_session$data;
  readonly " $fragmentSpreads": FragmentRefs<"BrowserSession_session">;
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
  "name": "BrowserSession_session",
  "selections": [
    (v0/*: any*/),
    (v1/*: any*/),
    {
      "alias": null,
      "args": null,
      "concreteType": "Authentication",
      "kind": "LinkedField",
      "name": "lastAuthentication",
      "plural": false,
      "selections": [
        (v0/*: any*/),
        (v1/*: any*/)
      ],
      "storageKey": null
    }
  ],
  "type": "BrowserSession",
  "abstractKey": null
};
})();

(node as any).hash = "04d6adf0b2a1bf2098938ef30f195c4a";

export default node;
