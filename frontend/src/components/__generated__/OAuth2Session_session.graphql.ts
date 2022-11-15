/**
 * @generated SignedSource<<599452efb8ce96e81a5e9500668ff055>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { Fragment, ReaderFragment } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type OAuth2Session_session$data = {
  readonly client: {
    readonly clientId: string;
    readonly clientName: string | null;
    readonly clientUri: any | null;
    readonly id: string;
  };
  readonly id: string;
  readonly scope: string;
  readonly " $fragmentType": "OAuth2Session_session";
};
export type OAuth2Session_session$key = {
  readonly " $data"?: OAuth2Session_session$data;
  readonly " $fragmentSpreads": FragmentRefs<"OAuth2Session_session">;
};

const node: ReaderFragment = (function(){
var v0 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "id",
  "storageKey": null
};
return {
  "argumentDefinitions": [],
  "kind": "Fragment",
  "metadata": null,
  "name": "OAuth2Session_session",
  "selections": [
    (v0/*: any*/),
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
        (v0/*: any*/),
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
};
})();

(node as any).hash = "d9fa36c7f93b7cef4d5a038d19f768b1";

export default node;
