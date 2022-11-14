/**
 * @generated SignedSource<<bafb31541b97839f32ff9790773ff904>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { Fragment, ReaderFragment } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type CompatSsoLogin_login$data = {
  readonly id: string;
  readonly redirectUri: any;
  readonly " $fragmentType": "CompatSsoLogin_login";
};
export type CompatSsoLogin_login$key = {
  readonly " $data"?: CompatSsoLogin_login$data;
  readonly " $fragmentSpreads": FragmentRefs<"CompatSsoLogin_login">;
};

const node: ReaderFragment = {
  "argumentDefinitions": [],
  "kind": "Fragment",
  "metadata": null,
  "name": "CompatSsoLogin_login",
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
      "name": "redirectUri",
      "storageKey": null
    }
  ],
  "type": "CompatSsoLogin",
  "abstractKey": null
};

(node as any).hash = "e1151a93f1ba4a56332b8aa6129f7bfe";

export default node;
