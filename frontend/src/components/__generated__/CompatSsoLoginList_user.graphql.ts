/**
 * @generated SignedSource<<4ace8ea8668e3dc638df21400c690bd8>>
 * @lightSyntaxTransform
 * @nogrep
 */

/* tslint:disable */
/* eslint-disable */
// @ts-nocheck

import { ReaderFragment, RefetchableFragment } from 'relay-runtime';
import { FragmentRefs } from "relay-runtime";
export type CompatSsoLoginList_user$data = {
  readonly compatSsoLogins: {
    readonly edges: ReadonlyArray<{
      readonly node: {
        readonly id: string;
        readonly " $fragmentSpreads": FragmentRefs<"CompatSsoLogin_login">;
      };
    }>;
  };
  readonly id: string;
  readonly " $fragmentType": "CompatSsoLoginList_user";
};
export type CompatSsoLoginList_user$key = {
  readonly " $data"?: CompatSsoLoginList_user$data;
  readonly " $fragmentSpreads": FragmentRefs<"CompatSsoLoginList_user">;
};

import CompatSsoLoginListQuery_graphql from './CompatSsoLoginListQuery.graphql';

const node: ReaderFragment = (function(){
var v0 = [
  "compatSsoLogins"
],
v1 = {
  "alias": null,
  "args": null,
  "kind": "ScalarField",
  "name": "id",
  "storageKey": null
};
return {
  "argumentDefinitions": [
    {
      "kind": "RootArgument",
      "name": "count"
    },
    {
      "kind": "RootArgument",
      "name": "cursor"
    }
  ],
  "kind": "Fragment",
  "metadata": {
    "connection": [
      {
        "count": "count",
        "cursor": "cursor",
        "direction": "forward",
        "path": (v0/*: any*/)
      }
    ],
    "refetch": {
      "connection": {
        "forward": {
          "count": "count",
          "cursor": "cursor"
        },
        "backward": null,
        "path": (v0/*: any*/)
      },
      "fragmentPathInResult": [
        "node"
      ],
      "operation": CompatSsoLoginListQuery_graphql,
      "identifierField": "id"
    }
  },
  "name": "CompatSsoLoginList_user",
  "selections": [
    {
      "alias": "compatSsoLogins",
      "args": null,
      "concreteType": "CompatSsoLoginConnection",
      "kind": "LinkedField",
      "name": "__CompatSsoLoginList_user_compatSsoLogins_connection",
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
                  "args": null,
                  "kind": "FragmentSpread",
                  "name": "CompatSsoLogin_login"
                },
                {
                  "alias": null,
                  "args": null,
                  "kind": "ScalarField",
                  "name": "__typename",
                  "storageKey": null
                }
              ],
              "storageKey": null
            },
            {
              "alias": null,
              "args": null,
              "kind": "ScalarField",
              "name": "cursor",
              "storageKey": null
            }
          ],
          "storageKey": null
        },
        {
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
        }
      ],
      "storageKey": null
    },
    (v1/*: any*/)
  ],
  "type": "User",
  "abstractKey": null
};
})();

(node as any).hash = "cafc795d1bf9643ac6155c017e66c858";

export default node;
