/**
 * @generated SignedSource<<d3404a632e1928901a9a8ec12357528d>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { Fragment, ReaderFragment } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type CompatSsoLoginList_user$data = {
  readonly compatSsoLogins: {
    readonly edges: ReadonlyArray<{
      readonly node: {
        readonly " $fragmentSpreads": FragmentRefs<"CompatSsoLogin_login">;
      };
    }>;
  };
  readonly " $fragmentType": "CompatSsoLoginList_user";
};
export type CompatSsoLoginList_user$key = {
  readonly " $data"?: CompatSsoLoginList_user$data;
  readonly " $fragmentSpreads": FragmentRefs<"CompatSsoLoginList_user">;
};

const node: ReaderFragment = {
  "argumentDefinitions": [],
  "kind": "Fragment",
  "metadata": null,
  "name": "CompatSsoLoginList_user",
  "selections": [
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
                {
                  "args": null,
                  "kind": "FragmentSpread",
                  "name": "CompatSsoLogin_login"
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
  "type": "User",
  "abstractKey": null
};

(node as any).hash = "b70f4b63784afe8f1f69c78198194cc9";

export default node;
